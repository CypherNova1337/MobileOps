package dev.cyphernova.mobileops.core.iot

/**
 * The service catalogue for the things a general-purpose port list misses.
 *
 * A scanner that knows about SSH and HTTP tells you a building has computers in it. On a site
 * whose value is in its devices — a hospital, a plant, a warehouse — the interesting ports are
 * the ones nobody puts in a top-1000 list: DICOM, BACnet, Modbus, HL7, MQTT. Those are where the
 * findings are, and they are also where the danger is, which is why fragility is recorded
 * alongside the name rather than left to the operator's memory.
 */
object IotPorts {

    /**
     * How much a device minds being probed.
     *
     * This is not a footnote. A great deal of operational and medical equipment runs a TCP stack
     * written for a closed network and will fault, reboot or stop responding under a scan that a
     * server would not notice. On those devices an aggressive scan is not a finding, it is an
     * outage — and in a clinical setting an outage is a patient safety event. The scanner uses
     * this to back off automatically rather than relying on the operator to remember.
     */
    enum class Fragility(val label: String) {
        /** A general-purpose host. Scan normally. */
        ROBUST("robust"),

        /** Embedded, but built to be talked to. Keep concurrency modest. */
        EMBEDDED("embedded — probe gently"),

        /**
         * Known to fall over. One connection at a time, no banner grabbing beyond what the
         * protocol defines, and nothing that writes.
         */
        FRAGILE("fragile — one connection at a time, read-only"),
    }

    /** What sort of thing a port implies, which is what the classifier reasons over. */
    enum class Domain {
        GENERAL,
        MEDICAL,
        BUILDING,
        INDUSTRIAL,
        CAMERA,
        PRINTER,
        VOIP,
        MESSAGING,
        NETWORK,
    }

    data class Service(
        val port: Int,
        val name: String,
        val domain: Domain,
        val fragility: Fragility,
        /** Why an assessor cares that this is answering. */
        val significance: String,
    )

    fun serviceAt(port: Int): Service? = BY_PORT[port]

    fun domainOf(port: Int): Domain = BY_PORT[port]?.domain ?: Domain.GENERAL

    /** The most cautious fragility across everything found on one host. */
    fun fragilityAcross(ports: Collection<Int>): Fragility = ports
        .mapNotNull { BY_PORT[it]?.fragility }
        .maxByOrNull { it.ordinal }
        ?: Fragility.ROBUST

    /** Every port this catalogue knows, for a scan that wants the whole set. */
    val allPorts: List<Int> get() = BY_PORT.keys.sorted()

    /** Ports worth scanning where the operator has said the site is of this kind. */
    fun portsFor(domain: Domain): List<Int> =
        BY_PORT.values.filter { it.domain == domain }.map { it.port }.sorted()

    private val SERVICES = listOf(
        // Medical. DICOM and HL7 are the two that carry patient data, and both were designed
        // for a trusted network — neither authenticates by default.
        Service(
            104, "dicom", Domain.MEDICAL, Fragility.FRAGILE,
            "DICOM, the imaging protocol. The default configuration authenticates callers only " +
                "by AE title, which is a name the caller chooses. An answering node will often " +
                "list and release studies to anyone who asks politely.",
        ),
        Service(
            11112, "dicom-tls", Domain.MEDICAL, Fragility.FRAGILE,
            "The registered DICOM port. Same protocol and usually the same weak association " +
                "checking as port 104.",
        ),
        Service(
            2575, "hl7-mllp", Domain.MEDICAL, Fragility.FRAGILE,
            "HL7 over MLLP, which carries admissions, orders and results between clinical " +
                "systems. The framing has no authentication and no encryption at all — anything " +
                "that can reach this port can read and inject clinical messages.",
        ),
        Service(
            6661, "hl7-alt", Domain.MEDICAL, Fragility.FRAGILE,
            "An HL7 interface engine listener. Same exposure as 2575.",
        ),
        Service(
            3200, "medical-alt", Domain.MEDICAL, Fragility.FRAGILE,
            "A port used by several patient-monitoring and telemetry gateways.",
        ),

        // Building automation. In a hospital these run the things that keep the building
        // habitable, and they are almost always flat and unauthenticated.
        Service(
            47808, "bacnet", Domain.BUILDING, Fragility.FRAGILE,
            "BACnet/IP, the building automation protocol — HVAC, lighting, pressure differentials, " +
                "sometimes medical gas and door control. It has no authentication in its base " +
                "form: anything that can reach it can read every point, and usually write them.",
        ),
        Service(
            1911, "niagara-fox", Domain.BUILDING, Fragility.FRAGILE,
            "Tridium Niagara Fox, a building-management platform. The handshake discloses station " +
                "name, host ID and version before any credential is offered.",
        ),
        Service(
            4911, "niagara-foxs", Domain.BUILDING, Fragility.FRAGILE,
            "Niagara Fox over TLS. Same platform as 1911.",
        ),
        Service(
            3671, "knx", Domain.BUILDING, Fragility.FRAGILE,
            "KNXnet/IP building control. Unauthenticated in its common deployment.",
        ),

        // Industrial. Present in hospitals too — plant rooms, generators, chillers.
        Service(
            502, "modbus", Domain.INDUSTRIAL, Fragility.FRAGILE,
            "Modbus/TCP. No authentication exists in the protocol: every reachable register can " +
                "be read, and on most devices written. This is the canonical example of a " +
                "protocol that assumes a physically isolated network.",
        ),
        Service(
            102, "s7comm", Domain.INDUSTRIAL, Fragility.FRAGILE,
            "Siemens S7 communications, used by S7-300/400/1200/1500 controllers.",
        ),
        Service(
            44818, "ethernet-ip", Domain.INDUSTRIAL, Fragility.FRAGILE,
            "EtherNet/IP/CIP, used by Allen-Bradley and Rockwell equipment. Identity can be read " +
                "unauthenticated.",
        ),
        Service(
            20000, "dnp3", Domain.INDUSTRIAL, Fragility.FRAGILE,
            "DNP3, used in utilities and larger plant. Authentication is optional and rarely on.",
        ),

        // Cameras. A hospital's cameras see waiting rooms, corridors and sometimes wards.
        Service(
            554, "rtsp", Domain.CAMERA, Fragility.EMBEDDED,
            "RTSP video. A stream that answers DESCRIBE without credentials is a live feed " +
                "readable by anyone on the segment.",
        ),
        Service(
            8554, "rtsp-alt", Domain.CAMERA, Fragility.EMBEDDED,
            "An alternative RTSP port, common on NVRs and consumer cameras.",
        ),
        Service(
            37777, "dahua", Domain.CAMERA, Fragility.EMBEDDED,
            "The Dahua proprietary camera protocol, which identifies the vendor on its own.",
        ),
        Service(
            34567, "hisilicon-dvr", Domain.CAMERA, Fragility.EMBEDDED,
            "A DVR management port common to HiSilicon-based recorders, many of which shipped " +
                "with fixed credentials.",
        ),

        // Messaging and IoT transports, which are where sensor estates converge.
        Service(
            1883, "mqtt", Domain.MESSAGING, Fragility.EMBEDDED,
            "MQTT. Brokers are routinely deployed with anonymous access left on, and a broker " +
                "that accepts an anonymous subscribe to '#' hands over every message on the " +
                "estate — sensor readings, commands, and frequently credentials.",
        ),
        Service(
            8883, "mqtt-tls", Domain.MESSAGING, Fragility.EMBEDDED,
            "MQTT over TLS. Worth checking whether the broker also accepts anonymous clients.",
        ),
        Service(
            5683, "coap", Domain.MESSAGING, Fragility.EMBEDDED,
            "CoAP, the constrained-device HTTP analogue. Its resource directory is readable " +
                "without authentication by design.",
        ),
        Service(
            5672, "amqp", Domain.MESSAGING, Fragility.EMBEDDED,
            "AMQP message broker.",
        ),

        // Printers and multifunction devices, which hold scanned documents and address books.
        Service(
            9100, "jetdirect", Domain.PRINTER, Fragility.EMBEDDED,
            "Raw print. Accepts jobs from anyone on the segment, and on many devices also PJL " +
                "commands that read the filesystem.",
        ),
        Service(
            515, "lpd", Domain.PRINTER, Fragility.EMBEDDED,
            "Line printer daemon, generally unauthenticated.",
        ),
        Service(
            631, "ipp", Domain.PRINTER, Fragility.EMBEDDED,
            "Internet Printing Protocol. Its attributes disclose the model, firmware and often " +
                "the queue contents.",
        ),

        // Voice. Extensions and provisioning are both worth having.
        Service(
            5060, "sip", Domain.VOIP, Fragility.EMBEDDED,
            "SIP. Worth checking for extension enumeration and unauthenticated registration.",
        ),
        Service(
            2000, "skinny", Domain.VOIP, Fragility.EMBEDDED,
            "Cisco SCCP, used by older Cisco handsets.",
        ),

        // Embedded management surfaces that keep turning up on device networks.
        Service(
            23, "telnet", Domain.GENERAL, Fragility.EMBEDDED,
            "Telnet. Credentials in cleartext, and on embedded devices frequently a fixed " +
                "engineering account.",
        ),
        Service(
            2323, "telnet-alt", Domain.GENERAL, Fragility.EMBEDDED,
            "Telnet on an alternative port, a common IoT default.",
        ),
        Service(
            7547, "cwmp", Domain.NETWORK, Fragility.EMBEDDED,
            "TR-069 remote management. It exists so an operator can reconfigure the device " +
                "remotely, which is exactly what makes it worth finding.",
        ),
        Service(
            4786, "smart-install", Domain.NETWORK, Fragility.FRAGILE,
            "Cisco Smart Install. Unauthenticated configuration retrieval and replacement.",
        ),
        Service(
            161, "snmp", Domain.NETWORK, Fragility.EMBEDDED,
            "SNMP. A default community string gives a full inventory of the device and often " +
                "its configuration.",
        ),
    )

    private val BY_PORT: Map<Int, Service> = SERVICES.associateBy { it.port }
}
