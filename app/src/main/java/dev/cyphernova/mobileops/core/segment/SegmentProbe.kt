package dev.cyphernova.mobileops.core.segment

import dev.cyphernova.mobileops.core.net.Cidr4

/**
 * The reasoning behind a segmentation test: which addresses are worth trying, and what an answer
 * from each one means.
 *
 * Segmentation is usually the finding that decides a report. A guest network with a weak
 * passphrase is a footnote if it is genuinely isolated and the whole engagement if it is not,
 * and the same is true of any segment holding equipment — the protocols that equipment speaks
 * have no authentication of their own, so the network separating them *is* the control.
 *
 * The test is therefore not "can I find hosts" but "can I reach places I should not be able to".
 * That distinction shapes everything here: the probe list is built from where the interesting
 * segments conventionally live rather than from a sweep, because a phone cannot scan RFC1918 and
 * the answer is usually sitting on a handful of predictable addresses.
 */
object SegmentProbe {

    /** Where a probe was aimed, and what reaching it would prove. */
    data class Candidate(val address: String, val rationale: String)

    /** Whether an address is in one of the private ranges RFC 1918 sets aside. */
    fun isPrivate(address: String): Boolean {
        val value = Cidr4.parseAddress(address) ?: return false
        val first = (value shr 24) and 0xFF
        val second = (value shr 16) and 0xFF
        return when (first) {
            10L -> true
            172L -> second in 16..31
            192L -> second == 168L
            else -> false
        }
    }

    /** True for the link-local block a host gives itself when DHCP fails. */
    fun isLinkLocal(address: String): Boolean {
        val value = Cidr4.parseAddress(address) ?: return false
        return ((value shr 24) and 0xFF) == 169L && ((value shr 16) and 0xFF) == 254L
    }

    /**
     * Addresses worth trying from a host sitting on [cidr].
     *
     * Built from convention rather than exhaustion. Every one of these is where an infrastructure
     * device conventionally sits — the first address of a subnet, in the ranges that networks are
     * conventionally carved out of — so reaching any of them means traffic is being routed
     * somewhere it was probably not meant to go.
     *
     * The caller's own subnet is excluded: reaching that proves nothing about segmentation.
     */
    fun candidatesFor(cidr: String): List<Candidate> {
        val ourNetwork = networkOf(cidr)
        val candidates = linkedMapOf<String, Candidate>()

        fun offer(address: String, rationale: String) {
            if (networkOf("$address/24") == ourNetwork) return
            candidates.putIfAbsent(address, Candidate(address, rationale))
        }

        // Neighbouring /24s inside the same 192.168 space, where a small site puts its segments.
        val ourSecond = secondOctetOf(cidr)
        val ourThird = thirdOctetOf(cidr)
        if (ourSecond == 168L) {
            NEIGHBOUR_OFFSETS.forEach { offset ->
                val third = ourThird + offset
                if (third in 0..255) {
                    offer(
                        "192.168.$third.1",
                        "the gateway of a neighbouring /24, one step from this segment",
                    )
                }
            }
            COMMON_192_SEGMENTS.forEach { third ->
                offer("192.168.$third.1", "a conventional segment address in the same space")
            }
        }

        // The ranges a larger site carves its segments out of. A guest network in 192.168 space
        // reaching into 10/8 is routing between two different address plans, which is rarely an
        // accident of configuration and almost always a missing rule.
        COMMON_TEN_SEGMENTS.forEach { address ->
            offer(address, "a conventional address in 10/8, a different address plan entirely")
        }
        COMMON_172_SEGMENTS.forEach { address ->
            offer(address, "a conventional address in the 172.16/12 space")
        }

        return candidates.values.toList()
    }

    /**
     * Addresses that should answer nothing, used to check the probe itself before believing it.
     *
     * A cross-segment result is only meaningful if a *negative* one is possible. Plenty of
     * networks answer indiscriminately for addresses that do not exist — a NAT that hairpins, an
     * upstream that replies to anything in private space, a captive portal intercepting every
     * flow — and against any of those every probe "succeeds" and the finding is manufactured
     * rather than observed.
     *
     * These are deliberately in the private ranges but at addresses nothing is conventionally
     * assigned to, and they exclude the caller's own subnet for the same reason the candidates do.
     * If one of them answers, the probe path is untrustworthy and the whole cross-segment result
     * has to be thrown away.
     */
    fun controlsFor(cidr: String): List<String> {
        val ourThird = thirdOctetOf(cidr)
        val ourSecond = secondOctetOf(cidr)
        return listOf(
            // A high .0/24 in 192.168 space that differs from the caller's own.
            "192.168.${if (ourSecond == 168L && ourThird == 253L) 251L else 253L}.253",
            "10.253.253.253",
            "172.31.253.253",
        ).filterNot { networkOf("$it/24") == networkOf(cidr) }
    }

    /**
     * The reverse-lookup name for an address.
     *
     * Useful because a resolver that answers this for an address outside the caller's own segment
     * knows about that segment — which is disclosure in itself, and often the first evidence that
     * a guest network is being served by the internal DNS infrastructure.
     */
    fun reverseName(address: String): String? {
        val octets = address.split('.')
        if (octets.size != 4 || octets.any { it.toIntOrNull() !in 0..255 }) return null
        return "${octets[3]}.${octets[2]}.${octets[1]}.${octets[0]}.in-addr.arpa"
    }

    /**
     * The service records that give away an Active Directory estate.
     *
     * A resolver that answers these has just named the domain controllers, and on a guest segment
     * that is both an information leak and a strong hint that the segment is not as separate as
     * it looks.
     */
    fun directoryRecordsFor(domain: String): List<Pair<String, String>> {
        val clean = domain.trim('.').lowercase()
        if (clean.isBlank()) return emptyList()
        return listOf(
            "_ldap._tcp.dc._msdcs.$clean" to "domain controllers",
            "_kerberos._tcp.$clean" to "Kerberos key distribution centres",
            "_ldap._tcp.$clean" to "LDAP servers",
            "_gc._tcp.$clean" to "global catalogue servers",
        )
    }

    /** What the resolver a network handed out says about that network. */
    enum class ResolverPosture(val label: String) {
        INTERNAL("internal resolver"),
        PUBLIC("public resolver"),
        SELF("the gateway itself"),
        NONE("none offered"),
    }

    fun resolverPosture(resolvers: List<String>, gateway: String?): ResolverPosture = when {
        resolvers.isEmpty() -> ResolverPosture.NONE
        gateway != null && resolvers.all { it == gateway } -> ResolverPosture.SELF
        resolvers.any { isPrivate(it) } -> ResolverPosture.INTERNAL
        else -> ResolverPosture.PUBLIC
    }

    /** Hosts on the caller's own subnet, which is how AP isolation gets tested. */
    fun peersOf(cidr: String, limit: Int = 254): List<String> {
        val network = Cidr4.parseAddress(cidr.substringBefore('/')) ?: return emptyList()
        val prefix = cidr.substringAfter('/', "24").toIntOrNull() ?: 24
        // [limit] does the bounding, so a large subnet is sampled rather than refused — the
        // first addresses of a /16 still hold its gateway and most of its infrastructure, and
        // skipping the isolation test entirely on a big network would be the worse answer.
        // Anything wider than a /16 is a sample too thin to mean anything.
        if (prefix < 16) return emptyList()
        val mask = if (prefix == 0) 0L else (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL
        val base = network and mask
        val size = (1L shl (32 - prefix)) - 2
        return (1..minOf(size, limit.toLong())).map { Cidr4.toDotted(base + it) }
    }

    private fun networkOf(cidr: String): Long {
        val value = Cidr4.parseAddress(cidr.substringBefore('/')) ?: return -1
        return value and 0xFFFFFF00L
    }

    private fun secondOctetOf(cidr: String): Long {
        val value = Cidr4.parseAddress(cidr.substringBefore('/')) ?: return -1
        return (value shr 16) and 0xFF
    }

    private fun thirdOctetOf(cidr: String): Long {
        val value = Cidr4.parseAddress(cidr.substringBefore('/')) ?: return -1
        return (value shr 8) and 0xFF
    }

    /** One step either side catches the common "guest is the segment next door" layout. */
    private val NEIGHBOUR_OFFSETS = listOf(-2L, -1L, 1L, 2L)

    private val COMMON_192_SEGMENTS = listOf(0L, 1L, 2L, 10L, 20L, 50L, 100L, 200L)

    private val COMMON_TEN_SEGMENTS = listOf(
        "10.0.0.1", "10.0.1.1", "10.1.1.1", "10.1.10.1", "10.10.10.1", "10.100.0.1",
    )

    private val COMMON_172_SEGMENTS = listOf("172.16.0.1", "172.16.1.1", "172.20.0.1", "172.31.0.1")
}

/**
 * What an address outside the local segment actually is.
 *
 * Counting every reachable address as another segment of the estate overstates the finding twice
 * over, and a live run showed both ways:
 *
 *  - `192.168.100.1` answered, and it is the cable modem. That address is the DOCSIS management
 *    default — Arris, Motorola, Netgear and Technicolor all use it — and a router forwards to it
 *    by design so its owner can see the line. Reachable modem management is worth reporting; it
 *    is not the estate's internal segmentation failing.
 *  - `192.168.10.1` and `192.168.20.1` answered ICMP and served nothing. A router replies to ICMP
 *    for *every* address it holds, from any interface, so a ping answered by a `.1` is as easily
 *    the gateway talking about itself as proof that traffic reaches that segment at all.
 *
 * A finding that cannot tell those apart from a genuinely routed path is not evidence, so the
 * three are kept apart and only the last one carries the weight.
 */
object ReachedAddress {

    enum class Kind {
        /** The cable modem's management address, reachable by design. */
        UPSTREAM_EQUIPMENT,

        /** A TCP service answered, so something really is reachable over there. */
        ROUTED_SERVICE,

        /** Only ICMP answered, on an address a router would hold itself. */
        GATEWAY_ECHO,
    }

    /** The DOCSIS cable-modem management address, the same on every vendor's hardware. */
    const val CABLE_MODEM = "192.168.100.1"

    fun classify(address: String, answeringPort: Int?): Kind = when {
        address == CABLE_MODEM -> Kind.UPSTREAM_EQUIPMENT
        answeringPort != null -> Kind.ROUTED_SERVICE
        // A router answers for its own interfaces. Only a `.1` is ambiguous in that way; an
        // arbitrary host inside the range answering ICMP really is that range being reached.
        address.endsWith(".1") -> Kind.GATEWAY_ECHO
        else -> Kind.ROUTED_SERVICE
    }

    fun explain(kind: Kind): String = when (kind) {
        Kind.UPSTREAM_EQUIPMENT ->
            "the cable modem's management address, which a router forwards to by design"
        Kind.ROUTED_SERVICE ->
            "a service answered, so traffic from this segment genuinely reaches it"
        Kind.GATEWAY_ECHO ->
            "only ICMP answered on a gateway address, which the router may be answering for " +
                "its own interface rather than routing anywhere"
    }
}
