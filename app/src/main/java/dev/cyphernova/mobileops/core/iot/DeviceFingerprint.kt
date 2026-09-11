package dev.cyphernova.mobileops.core.iot

/**
 * Works out what a host on the network actually is.
 *
 * A port scan produces a list of numbers. On a site whose risk lives in its equipment, the list
 * is not the finding — "this is an imaging node", "this is the chiller controller", "this is a
 * camera" is. Everything downstream depends on that classification: what it means, how badly it
 * would matter, and how gently it has to be handled.
 *
 * Nothing here touches the network. It reasons over evidence another module already collected —
 * open ports, banners, whatever name the host volunteered over mDNS, NetBIOS or DHCP, and the
 * vendor prefix of its MAC — which keeps the judgement testable and keeps the probing in one place.
 */
object DeviceFingerprint {

    enum class Category(val label: String) {
        MEDICAL_IMAGING("Medical imaging (DICOM/PACS)"),
        MEDICAL_INTERFACE("Clinical interface (HL7)"),
        PATIENT_MONITORING("Patient monitoring / telemetry"),
        BUILDING_CONTROL("Building automation"),
        INDUSTRIAL_CONTROL("Industrial control"),
        IP_CAMERA("IP camera / recorder"),
        PRINTER("Printer / multifunction"),
        VOIP("VoIP handset or gateway"),
        IOT_BROKER("IoT message broker"),
        IOT_SENSOR("Constrained IoT device"),
        NETWORK_DEVICE("Network infrastructure"),
        STORAGE("Network storage"),
        SERVER("General-purpose server"),
        ENDPOINT("Workstation or endpoint"),
        UNKNOWN("Unidentified"),
    }

    /**
     * How firmly the evidence supports the verdict. Reported rather than hidden, because acting
     * on a guess and acting on a protocol handshake are different decisions — particularly when
     * the decision is whether it is safe to scan something harder.
     */
    enum class Confidence(val label: String) {
        /** A protocol spoke and identified itself. */
        CONFIRMED("confirmed"),

        /** A port that belongs to one thing and little else is answering. */
        STRONG("strong"),

        /** Names or a vendor prefix point one way without proving it. */
        INFERRED("inferred"),
    }

    /** Everything known about one host, gathered by the modules that do touch the network. */
    data class Evidence(
        val address: String,
        val openPorts: Set<Int> = emptySet(),
        val banners: Map<Int, String> = emptyMap(),
        /** Any name the host volunteered — mDNS, NetBIOS, SSDP, or a DHCP lease. */
        val names: List<String> = emptyList(),
        val macVendor: String? = null,
        /** Service strings from mDNS or SSDP, e.g. `_ipp._tcp` or a UPnP device type. */
        val advertisedServices: List<String> = emptyList(),
    ) {
        val searchableText: String
            get() = (names + advertisedServices + banners.values + listOfNotNull(macVendor))
                .joinToString(" ")
                .lowercase()
    }

    data class Verdict(
        val category: Category,
        val confidence: Confidence,
        val fragility: IotPorts.Fragility,
        /** What the evidence was, so a surprising verdict can be argued with. */
        val basis: String,
        /** Why an assessor should care that this is here. */
        val significance: String,
    )

    fun classify(evidence: Evidence): Verdict {
        // Port evidence outranks name evidence: a device can be called anything, but a protocol
        // answering on its registered port is a fact about what it runs.
        val byPort = portVerdict(evidence)
        val byName = nameVerdict(evidence)

        if (byPort != null) {
            // Where both agree, the name usually says the more useful half. A printer found on
            // 631 gets "IPP discloses the model"; the banner that also named it a Lexmark gets
            // "holds scanned documents and scan-to-folder credentials", which is what an
            // assessor actually needs. Keeping both loses nothing.
            if (byName != null && byName.category == byPort.category) {
                return byPort.copy(
                    confidence = Confidence.CONFIRMED,
                    basis = "${byPort.basis}, and ${byName.basis}",
                    significance = listOf(byPort.significance, byName.significance)
                        .filter { it.isNotBlank() }
                        .joinToString(" "),
                )
            }
            return byPort
        }

        return byName ?: fallback(evidence)
    }

    private fun portVerdict(evidence: Evidence): Verdict? {
        val ports = evidence.openPorts
        val fragility = IotPorts.fragilityAcross(ports)

        fun verdict(category: Category, port: Int, confidence: Confidence = Confidence.STRONG): Verdict {
            val service = IotPorts.serviceAt(port)
            return Verdict(
                category = category,
                confidence = confidence,
                fragility = fragility,
                basis = "port $port (${service?.name ?: "unknown"}) is answering",
                significance = service?.significance ?: "",
            )
        }

        // Ordered by how much the finding matters on a site of this kind, so a host that is both
        // an imaging node and a web server is reported as the former.
        ports.firstOrNull { it in DICOM_PORTS }?.let { return verdict(Category.MEDICAL_IMAGING, it) }
        ports.firstOrNull { it in HL7_PORTS }?.let { return verdict(Category.MEDICAL_INTERFACE, it) }
        ports.firstOrNull { it in INDUSTRIAL_PORTS }?.let { return verdict(Category.INDUSTRIAL_CONTROL, it) }
        ports.firstOrNull { it in BUILDING_PORTS }?.let { return verdict(Category.BUILDING_CONTROL, it) }
        ports.firstOrNull { it in CAMERA_PORTS }?.let { return verdict(Category.IP_CAMERA, it) }
        ports.firstOrNull { it in BROKER_PORTS }?.let { return verdict(Category.IOT_BROKER, it) }
        ports.firstOrNull { it in COAP_PORTS }?.let { return verdict(Category.IOT_SENSOR, it) }
        ports.firstOrNull { it in PRINTER_PORTS }?.let { return verdict(Category.PRINTER, it) }
        ports.firstOrNull { it in VOIP_PORTS }?.let { return verdict(Category.VOIP, it) }
        return null
    }

    private fun nameVerdict(evidence: Evidence): Verdict? {
        val text = evidence.searchableText
        if (text.isBlank()) return null

        NAME_SIGNALS.firstOrNull { (pattern, _) -> pattern.containsMatchIn(text) }?.let { (pattern, hit) ->
            val (category, significance) = hit
            return Verdict(
                category = category,
                confidence = Confidence.INFERRED,
                // A name is not enough to conclude a device is robust, so anything a name points
                // at as equipment is handled as embedded until a protocol says otherwise.
                fragility = maxOf(
                    IotPorts.fragilityAcross(evidence.openPorts),
                    if (category in EQUIPMENT) IotPorts.Fragility.EMBEDDED else IotPorts.Fragility.ROBUST,
                ),
                basis = "the name or vendor matched '${pattern.pattern}'",
                significance = significance,
            )
        }
        return null
    }

    /** With no equipment signal, the open ports still separate a server from an endpoint. */
    private fun fallback(evidence: Evidence): Verdict {
        val ports = evidence.openPorts
        val fragility = IotPorts.fragilityAcross(ports)

        val category = when {
            ports.any { it in NETWORK_PORTS } -> Category.NETWORK_DEVICE
            ports.any { it in STORAGE_PORTS } -> Category.STORAGE
            ports.any { it in SERVER_PORTS } -> Category.SERVER
            ports.isNotEmpty() -> Category.ENDPOINT
            else -> Category.UNKNOWN
        }

        return Verdict(
            category = category,
            confidence = if (category == Category.UNKNOWN) Confidence.INFERRED else Confidence.INFERRED,
            fragility = fragility,
            basis = if (ports.isEmpty()) {
                "the host answered discovery but no scanned port is open"
            } else {
                "open ports ${ports.sorted().joinToString()}"
            },
            significance = "",
        )
    }

    /** Categories whose devices should be assumed delicate until proven otherwise. */
    private val EQUIPMENT = setOf(
        Category.MEDICAL_IMAGING,
        Category.MEDICAL_INTERFACE,
        Category.PATIENT_MONITORING,
        Category.BUILDING_CONTROL,
        Category.INDUSTRIAL_CONTROL,
        Category.IP_CAMERA,
        Category.IOT_SENSOR,
    )

    private val DICOM_PORTS = setOf(104, 11112)
    private val HL7_PORTS = setOf(2575, 6661)
    private val INDUSTRIAL_PORTS = setOf(502, 102, 44818, 20000)
    private val BUILDING_PORTS = setOf(47808, 1911, 4911, 3671)
    private val CAMERA_PORTS = setOf(554, 8554, 37777, 34567)
    private val BROKER_PORTS = setOf(1883, 8883, 5672)
    private val COAP_PORTS = setOf(5683)
    private val PRINTER_PORTS = setOf(9100, 515, 631)
    private val VOIP_PORTS = setOf(5060, 2000)
    private val NETWORK_PORTS = setOf(161, 7547, 4786, 1723)
    private val STORAGE_PORTS = setOf(2049, 548, 873)
    private val SERVER_PORTS = setOf(22, 1433, 3306, 5432, 6379, 27017, 25, 110, 143)

    /**
     * Vendor and product names that identify equipment before any protocol does.
     *
     * Deliberately weighted towards the estates whose risk is physical rather than informational,
     * because those are the ones a general-purpose scanner is worst at naming.
     */
    private val NAME_SIGNALS: List<Pair<Regex, Pair<Category, String>>> = listOf(
        Regex("""dicom|pacs|\bpacs\b|carestream|sectra|agfa|synapse|centricity""") to
            (Category.MEDICAL_IMAGING to
                "An imaging or archive node. These hold patient studies and their access control " +
                    "is frequently an AE title rather than a credential."),
        Regex("""\bhl7\b|mirth|rhapsody|cloverleaf|interface\s?engine|corepoint""") to
            (Category.MEDICAL_INTERFACE to
                "A clinical interface engine. Everything passing through it is patient data, in " +
                    "cleartext, usually unauthenticated at the transport."),
        Regex("""philips|draeger|drager|spacelabs|mindray|welch\s?allyn|nihon\s?kohden|masimo|
            |infusion|alaris|baxter|b\.?braun|carefusion|pyxis|omnicell|telemetry|patient\s?monitor"""
            .trimMargin().replace("\n", "")) to
            (Category.PATIENT_MONITORING to
                "Clinical equipment. Anything that touches a device delivering therapy or " +
                    "reporting vitals is a patient-safety question first and a security finding " +
                    "second — probe read-only and never aggressively."),
        Regex("""bacnet|tridium|niagara|johnson\s?controls|honeywell|siemens\s?desigo|
            |schneider|trane|carrier\b|chiller|\bahu\b|\bhvac\b|building\s?automation"""
            .trimMargin().replace("\n", "")) to
            (Category.BUILDING_CONTROL to
                "Building automation. In a clinical or laboratory setting this can control room " +
                    "pressure differentials, temperature for stored medicines, and sometimes " +
                    "door release — which makes it a physical-safety system, not a facilities one."),
        Regex("""modbus|allen[-\s]?bradley|rockwell|\bplc\b|\bscada\b|\bhmi\b|wago|beckhoff|omron""") to
            (Category.INDUSTRIAL_CONTROL to
                "Industrial control equipment. The protocols it speaks were designed for an " +
                    "isolated network and have no authentication."),
        Regex("""hikvision|dahua|axis\s?comm|vivotek|reolink|ubiquiti\s?protect|\bnvr\b|\bdvr\b|
            |ip\s?camera|camera""".trimMargin().replace("\n", "")) to
            (Category.IP_CAMERA to
                "A camera or recorder. Worth establishing what it overlooks and whether the " +
                    "stream is readable without credentials."),
        Regex("""jetdirect|laserjet|officejet|\bepson\b|\bbrother\b|\bricoh\b|\bxerox\b|
            |\bkyocera\b|\blexmark\b|\bcanon\b|printer|\bmfp\b""".trimMargin().replace("\n", "")) to
            (Category.PRINTER to
                "A printer or multifunction device. These hold scanned documents, address books " +
                    "and frequently stored domain credentials for scan-to-folder."),
        Regex("""polycom|yealink|grandstream|\bsnom\b|avaya|\bsip\b|\bvoip\b""") to
            (Category.VOIP to "A voice device."),
        Regex("""mosquitto|\bmqtt\b|rabbitmq|\bemqx\b|hivemq""") to
            (Category.IOT_BROKER to
                "A message broker. Where anonymous access is left on, subscribing to everything " +
                    "returns the whole estate's telemetry and commands."),
        Regex("""zigbee|z-wave|lorawan|\bcoap\b|particle|espressif|\besp32\b|tasmota|shelly|sonoff""") to
            (Category.IOT_SENSOR to "A constrained IoT device or its gateway."),
        Regex("""synology|\bqnap\b|truenas|freenas|netgear\s?readynas|western\s?digital""") to
            (Category.STORAGE to "Network storage. Worth checking for open shares."),
        Regex("""cisco|juniper|aruba|fortinet|mikrotik|ruckus|meraki|unifi|switch|router|firewall""") to
            (Category.NETWORK_DEVICE to
                "Network infrastructure. Its configuration defines the segmentation everything " +
                    "else depends on."),
    )
}
