package dev.cyphernova.mobileops.core.target

import dev.cyphernova.mobileops.core.evidence.Finding

/**
 * Pulls selectable hosts back out of the evidence log.
 *
 * The log is the record of what was seen, so the Targets tab derives from it rather than keeping
 * a second list that could disagree with it. What matters is *how* it derives: an earlier version
 * matched findings whose title began "Live host", which meant rewriting that title to cut report
 * noise silently emptied the Targets tab and left every host module with nothing to point at.
 *
 * So the harvest reads structured fields only. Modules report hosts in whichever shape suits them
 * — a census lists them together, a device identification names one, a peer sweep produces a set —
 * and every one of those is read, along with the finding's subject, because a finding about a host
 * names it there. Nothing here depends on prose.
 */
object HostHarvest {

    /**
     * The data keys that carry addresses. Adding a module means adding its key here, or reusing
     * one; it does not mean touching the UI.
     */
    val HOST_FIELDS = listOf("hosts", "addresses", "peers", "host", "gateway", "reached")

    /** Every address one finding mentions as somewhere reachable. */
    fun addressesIn(finding: Finding): List<String> =
        (HOST_FIELDS.flatMap { field -> finding.data[field].orEmpty().split(',') } + finding.subject)
            .map { it.trim() }
            .filter(::isIpv4)
            .distinct()

    /**
     * Every host the log knows about, in address order, with any name that was established for it.
     *
     * Names are collected across the whole log rather than per finding: the sweep finds an address
     * and NetBIOS or reverse DNS names it later, and the two only meet here.
     */
    fun hostsIn(findings: List<Finding>): List<Target.Host> {
        val names = findings.mapNotNull { finding ->
            val hostname = finding.data["hostname"]?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
            val address = finding.subject.trim().takeIf(::isIpv4) ?: return@mapNotNull null
            address to hostname
        }.toMap()

        return findings
            .flatMap(::addressesIn)
            .distinct()
            .map { address -> Target.Host(address, names[address]) }
            .sortedWith(ADDRESS_ORDER)
    }

    fun isIpv4(value: String): Boolean {
        val octets = value.split('.')
        return octets.size == 4 && octets.all { part ->
            part.isNotEmpty() && part.length <= 3 && part.all(Char::isDigit) && part.toInt() in 0..255
        }
    }

    /** Numeric, so .2 does not sort after .10 the way comparing the strings would. */
    private val ADDRESS_ORDER = compareBy<Target.Host> { host ->
        host.address.split('.').fold(0L) { value, octet ->
            (value shl 8) or (octet.toLongOrNull() ?: 0L)
        }
    }
}
