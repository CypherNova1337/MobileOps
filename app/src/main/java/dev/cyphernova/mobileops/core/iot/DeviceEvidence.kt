package dev.cyphernova.mobileops.core.iot

import dev.cyphernova.mobileops.core.evidence.Finding

/**
 * Gathers everything the whole run has learned about one host.
 *
 * Each module sees a slice. The port scan knows which ports answer and what they said on connect;
 * service discovery knows the NetBIOS name, the UPnP server string and the mDNS service types;
 * the sweep knows which address is the gateway. Classified from any one of those slices alone the
 * answers come out wrong in ways that are obvious to a reader — a router reported as a
 * workstation because nothing in its port list says router, a television reported the same way
 * because the module holding `_viziocast._tcp` was not the module doing the classifying.
 *
 * So the evidence is pooled from the log first and classified afterwards. The log is already the
 * record of what was seen; this reads it the way [dev.cyphernova.mobileops.core.target.HostHarvest]
 * reads it for addresses, and for the same reason.
 */
object DeviceEvidence {

    /** Fields that carry a service or product name worth classifying on. */
    private val NAME_FIELDS = listOf(
        "hostname", "name", "server", "services", "service_types", "device_name",
        "manufacturer", "model", "vendor", "workgroup",
    )

    private val BANNER_FIELDS = listOf("banner", "banners")

    /**
     * Everything known about [address], across every finding in [findings].
     *
     * @param gateway the subnet's gateway, where the run has established one. A host that routes
     *   for the segment is infrastructure whatever its port list looks like, and that is worth
     *   more than any inference drawn from the ports.
     */
    fun forHost(
        findings: List<Finding>,
        address: String,
        gateway: String? = null,
    ): DeviceFingerprint.Evidence {
        val mine = findings.filter { mentions(it, address) }

        val ports = mine.flatMap { finding ->
            finding.data["open_ports"].orEmpty().split(',').mapNotNull { it.trim().toIntOrNull() } +
                listOfNotNull(finding.data["port"]?.trim()?.toIntOrNull())
        }.toSet()

        val banners = mine.flatMap { finding ->
            BANNER_FIELDS.flatMap { field -> parseBanners(finding.data[field].orEmpty()) }
        }.toMap()

        val names = mine.flatMap { finding ->
            NAME_FIELDS.mapNotNull { field -> finding.data[field]?.takeIf { it.isNotBlank() } }
        }.distinct()

        return DeviceFingerprint.Evidence(
            address = address,
            openPorts = ports,
            banners = banners,
            names = names,
            advertisedServices = mine.mapNotNull { it.data["service_types"]?.takeIf { s -> s.isNotBlank() } },
            isGateway = gateway != null && gateway == address,
        )
    }

    /** Whether a finding is about this host, by subject or by any address field it carries. */
    private fun mentions(finding: Finding, address: String): Boolean {
        if (finding.subject.trim() == address) return true
        if (finding.subject.startsWith("$address:")) return true
        return ADDRESS_FIELDS.any { field ->
            finding.data[field].orEmpty().split(',').any { it.trim() == address }
        }
    }

    /**
     * Banners are recorded either as one string for a single port or as `port=text` pairs for a
     * whole host, so both shapes are read.
     */
    private fun parseBanners(value: String): List<Pair<Int, String>> {
        if (value.isBlank()) return emptyList()
        val pairs = value.split(';').mapNotNull { entry ->
            val port = entry.substringBefore('=', "").trim().toIntOrNull() ?: return@mapNotNull null
            port to entry.substringAfter('=').trim()
        }
        // A bare banner with no port prefix still carries a product name worth classifying on.
        return pairs.ifEmpty { listOf(0 to value) }
    }

    private val ADDRESS_FIELDS = listOf("host", "hosts", "address", "addresses")
}
