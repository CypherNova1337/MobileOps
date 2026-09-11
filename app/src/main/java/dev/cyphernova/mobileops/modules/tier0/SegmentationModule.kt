package dev.cyphernova.mobileops.modules.tier0

import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.discovery.Mdns
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleCategory
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule
import dev.cyphernova.mobileops.core.segment.SegmentProbe
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Tests whether the segment this device is on is actually separated from the ones that matter.
 *
 * This is usually the finding that decides a report. A guest network with a weak passphrase is a
 * footnote if it is genuinely isolated, and the whole engagement if it is not. The same holds for
 * any segment carrying equipment: the protocols that equipment speaks have no authentication of
 * their own, so the network separating them *is* the control, and whether it holds is the
 * question worth answering.
 *
 * Five things get tested, in the order they matter:
 *
 *  1. **Peer isolation** — can this device reach other clients on its own segment? Guest networks
 *     routinely claim isolation they do not implement.
 *  2. **Gateway management** — is the router's own administrative interface reachable from here?
 *  3. **Resolver posture** — was an internal resolver handed out, and what does it know?
 *  4. **Name disclosure** — will that resolver answer for addresses and domains belonging to
 *     other segments, and name the directory infrastructure while it is at it?
 *  5. **Cross-segment reach** — do conventional infrastructure addresses in other address plans
 *     answer at all?
 *
 * Reaching something is the finding. Nothing here tries to do anything with what it reaches.
 */
class SegmentationModule : PentestModule {
    override val id = "t0.net.segmentation"
    override val title = "Segmentation test"
    override val description =
        "Tests whether this segment is actually isolated: peer reachability, gateway management " +
            "exposure, what the resolver discloses, and whether other address plans answer. " +
            "Usually the finding that decides a report."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.ACTIVE
    override val category = ModuleCategory.NETWORK

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val position = LocalNetwork.position(context.androidContext)
            ?: return ModuleOutcome.Blocked(
                "No IPv4 address on any interface. Join the network under test first.",
            )

        if (!position.hasLocalSubnet) {
            return ModuleOutcome.Blocked(
                "This device is on a point-to-point link (${position.cidr}), which has no " +
                    "neighbours and no segmentation to test. Join the WiFi network under test.",
            )
        }

        emit(positionFinding(position))

        var crossings = 0
        crossings += testPeerIsolation(position, emit)
        crossings += testGatewayManagement(position, emit)
        crossings += testResolver(position, emit)
        crossings += testCrossSegment(position, emit)

        return when (crossings) {
            0 -> ModuleOutcome.Completed(
                "No isolation failure found from ${position.cidr}.",
            )
            else -> ModuleOutcome.Completed(
                "$crossings segmentation weakness(es) from ${position.cidr}.",
            )
        }
    }

    private fun positionFinding(position: NetworkPosition) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.INFO,
        title = "Attached to ${position.cidr}",
        subject = position.cidr,
        detail = "Address ${position.localAddress}/${position.prefixLength} on " +
            "${position.interfaceName ?: "unknown interface"}, gateway " +
            "${position.gateway ?: "unknown"}, resolvers " +
            "${position.dnsServers.joinToString().ifBlank { "none" }}. " +
            "Everything below is measured from here, so this is the baseline the rest of the " +
            "findings mean something relative to.",
        data = mapOf(
            "cidr" to position.cidr,
            "address" to position.localAddress,
            "gateway" to (position.gateway ?: ""),
            "resolvers" to position.dnsServers.joinToString(),
            "interface" to (position.interfaceName ?: ""),
        ),
    )

    /**
     * Whether other clients on this segment answer.
     *
     * A guest network that does not isolate its clients puts every visitor's laptop and phone on
     * a segment with every other visitor's. It is also the cheapest thing in the world to check
     * and is wrong surprisingly often, because the setting is per-SSID and easy to miss.
     */
    private suspend fun testPeerIsolation(
        position: NetworkPosition,
        emit: suspend (Finding) -> Unit,
    ): Int {
        val peers = SegmentProbe.peersOf(position.cidr, PEER_LIMIT)
            .filterNot { it == position.localAddress || it == position.gateway }
        if (peers.isEmpty()) return 0

        val alive = coroutineScope {
            peers.chunked(CONCURRENCY).flatMap { batch ->
                batch.map { peer -> async(Dispatchers.IO) { if (respondsTo(peer)) peer else null } }
                    .awaitAll()
            }.filterNotNull()
        }

        if (alive.isEmpty()) {
            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    severity = Severity.INFO,
                    title = "No peers reachable on ${position.cidr}",
                    subject = position.cidr,
                    detail = "No other client on this segment answered across the first " +
                        "$PEER_LIMIT addresses. That is consistent with client isolation being " +
                        "enabled, though it is also consistent with an empty network — it is " +
                        "evidence rather than proof.",
                    data = mapOf("peers_probed" to peers.size.toString(), "peers_alive" to "0"),
                ),
            )
            return 0
        }

        emit(
            Finding(
                moduleId = id,
                observedAtEpochMs = System.currentTimeMillis(),
                severity = Severity.HIGH,
                title = "Client isolation is not in effect on ${position.cidr}",
                subject = position.cidr,
                detail = "${alive.size} other host(s) on this segment answered directly: " +
                    alive.take(REPORT_LIMIT).joinToString() +
                    (if (alive.size > REPORT_LIMIT) " and ${alive.size - REPORT_LIMIT} more" else "") +
                    ". Every device on this network can reach every other one. On a guest or " +
                    "visitor segment that means each visitor is exposed to all the others, and " +
                    "any device that should not have been on this segment is now reachable from " +
                    "it.",
                data = mapOf(
                    "peers_alive" to alive.size.toString(),
                    "peers" to alive.take(REPORT_LIMIT).joinToString(),
                ),
            ),
        )
        return 1
    }

    /** Whether the router will talk administration to a client that should only be routed. */
    private suspend fun testGatewayManagement(
        position: NetworkPosition,
        emit: suspend (Finding) -> Unit,
    ): Int {
        val gateway = position.gateway ?: return 0
        val open = coroutineScope {
            MANAGEMENT_PORTS.map { port ->
                async(Dispatchers.IO) { if (isOpen(gateway, port)) port else null }
            }.awaitAll().filterNotNull()
        }
        if (open.isEmpty()) return 0

        emit(
            Finding(
                moduleId = id,
                observedAtEpochMs = System.currentTimeMillis(),
                severity = Severity.HIGH,
                title = "Gateway management reachable from this segment",
                subject = gateway,
                detail = "The gateway answers on ${open.joinToString { "$it/${MANAGEMENT_PORTS_NAMES[it]}" }}. " +
                    "A client segment does not need to reach its router's administration at all — " +
                    "it needs to be routed by it. Where this segment is a guest or visitor " +
                    "network, anyone on it can attempt the router's credentials, and a default " +
                    "or reused administrative password there gives up the whole network " +
                    "including the passphrases of every other SSID it serves.",
                data = mapOf("gateway" to gateway, "open_ports" to open.joinToString()),
            ),
        )
        return 1
    }

    /**
     * What the resolver handed out by DHCP will tell a client on this segment.
     *
     * An internal resolver on a guest network is a leak by itself, and a resolver that will
     * answer reverse lookups for other segments or name the directory infrastructure has
     * described the internal estate to someone who is supposed to be able to reach none of it.
     */
    private suspend fun testResolver(
        position: NetworkPosition,
        emit: suspend (Finding) -> Unit,
    ): Int {
        val resolver = position.dnsServers.firstOrNull() ?: return 0
        val posture = SegmentProbe.resolverPosture(position.dnsServers, position.gateway)

        if (posture == SegmentProbe.ResolverPosture.PUBLIC) {
            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    severity = Severity.INFO,
                    title = "Resolver is public",
                    subject = resolver,
                    detail = "The network handed out ${position.dnsServers.joinToString()}, which " +
                        "is outside the private ranges. A guest segment pointed at a public " +
                        "resolver cannot be used to enumerate the internal estate, which is the " +
                        "correct arrangement.",
                    data = mapOf("resolver" to resolver, "posture" to posture.name),
                ),
            )
            return 0
        }

        var findings = 0
        val disclosures = mutableListOf<String>()

        // A reverse lookup for an address in a different plan: answering it means this resolver
        // is authoritative for, or forwards to something that knows, that other segment.
        SegmentProbe.candidatesFor(position.cidr).take(REVERSE_PROBES).forEach { candidate ->
            val name = SegmentProbe.reverseName(candidate.address) ?: return@forEach
            resolve(resolver, name, Mdns.TYPE_PTR)?.let { answer ->
                disclosures += "${candidate.address} resolves to $answer"
            }
        }

        if (disclosures.isNotEmpty()) {
            findings++
            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    severity = Severity.MEDIUM,
                    title = "Resolver discloses hosts on other segments",
                    subject = resolver,
                    detail = "Reverse lookups for addresses outside this segment were answered: " +
                        disclosures.joinToString("; ") + ". The resolver on this segment knows " +
                        "about address space this segment should have no business with, which " +
                        "maps the internal estate for anyone who can ask — and it is a strong " +
                        "hint that the separation is administrative rather than enforced.",
                    data = mapOf("resolver" to resolver, "disclosures" to disclosures.joinToString("; ")),
                ),
            )
        }

        // A search domain turns a resolver into a directory of the organisation's infrastructure.
        val domain = searchDomain(position)
        if (domain != null) {
            val directory = mutableListOf<String>()
            SegmentProbe.directoryRecordsFor(domain).forEach { (record, description) ->
                resolve(resolver, record, Mdns.TYPE_SRV)?.let { target ->
                    directory += "$description: $target"
                }
            }
            if (directory.isNotEmpty()) {
                findings++
                emit(
                    Finding(
                        moduleId = id,
                        observedAtEpochMs = System.currentTimeMillis(),
                        severity = Severity.HIGH,
                        title = "Directory infrastructure named by the resolver",
                        subject = domain,
                        detail = "The resolver answered service records for '$domain': " +
                            directory.joinToString("; ") + ". These records exist so that domain " +
                            "members can find their controllers, which means this segment is " +
                            "being treated as one. A visitor network that can locate the domain " +
                            "controllers can also reach them, and everything that follows from " +
                            "that starts here.",
                        data = mapOf(
                            "resolver" to resolver,
                            "domain" to domain,
                            "records" to directory.joinToString("; "),
                        ),
                    ),
                )
            }
        }

        return findings
    }

    /**
     * Whether conventional infrastructure addresses in other address plans answer.
     *
     * The candidates are convention rather than a sweep — a phone cannot scan RFC1918 and does
     * not need to, because the answer is almost always sitting on one of a handful of addresses.
     */
    private suspend fun testCrossSegment(
        position: NetworkPosition,
        emit: suspend (Finding) -> Unit,
    ): Int {
        // Before believing any of this, check that a negative result is even possible. A NAT that
        // hairpins, an upstream that answers for anything in private space, or a portal
        // intercepting every flow will make every probe "succeed" — and then the finding is
        // manufactured rather than observed.
        val controls = SegmentProbe.controlsFor(position.cidr)
        val answeringControls = coroutineScope {
            controls.map { control ->
                async(Dispatchers.IO) {
                    if (CROSS_SEGMENT_PORTS.any { isOpen(control, it) } || respondsTo(control)) {
                        control
                    } else {
                        null
                    }
                }
            }.awaitAll().filterNotNull()
        }

        if (answeringControls.isNotEmpty()) {
            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    severity = Severity.INFO,
                    title = "Cross-segment probing is not reliable from here",
                    subject = position.cidr,
                    detail = "Control address(es) ${answeringControls.joinToString()} answered, " +
                        "and nothing is assigned to them. Something on the path replies " +
                        "regardless of what is asked for — a NAT that hairpins, an upstream that " +
                        "answers for any private address, or a portal intercepting every flow. " +
                        "Every cross-segment probe would 'succeed' against that, so no " +
                        "reachability conclusion is drawn here. Testing this properly needs a " +
                        "host on the other segment to compare against.",
                    data = mapOf(
                        "controls_probed" to controls.size.toString(),
                        "controls_answering" to answeringControls.joinToString(),
                    ),
                ),
            )
            return 0
        }

        val candidates = SegmentProbe.candidatesFor(position.cidr)
        val reached = coroutineScope {
            candidates.chunked(CONCURRENCY).flatMap { batch ->
                batch.map { candidate ->
                    async(Dispatchers.IO) {
                        val port = CROSS_SEGMENT_PORTS.firstOrNull { isOpen(candidate.address, it) }
                        if (port != null || respondsTo(candidate.address)) candidate to port else null
                    }
                }.awaitAll()
            }.filterNotNull()
        }

        if (reached.isEmpty()) {
            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    severity = Severity.INFO,
                    title = "No other address plan reachable from ${position.cidr}",
                    subject = position.cidr,
                    detail = "${candidates.size} conventional infrastructure address(es) in other " +
                        "private ranges were probed and none answered, and the control addresses " +
                        "confirmed a negative result is possible from here. That is what working " +
                        "segmentation looks like from this side — though it only covers the " +
                        "addresses convention puts equipment on, not every possible one.",
                    data = mapOf("probed" to candidates.size.toString(), "reached" to "0"),
                ),
            )
            return 0
        }

        emit(
            Finding(
                moduleId = id,
                observedAtEpochMs = System.currentTimeMillis(),
                severity = Severity.CRITICAL,
                title = "This segment routes into ${reached.size} other address plan(s)",
                subject = position.cidr,
                detail = "Reached from ${position.cidr}: " +
                    reached.joinToString("; ") { (candidate, port) ->
                        "${candidate.address}${port?.let { " on $it" } ?: " (responds to probe)"}"
                    } +
                    ". Control addresses in the same private ranges answered nothing, so the " +
                    "path is not simply replying to everything — these are real. Traffic from " +
                    "this segment is being routed into address space it has no reason to reach, " +
                    "and nothing dropped it on the way. If this is a guest or visitor network, " +
                    "that is the finding the engagement is about: everything downstream — " +
                    "equipment with no authentication of its own, management interfaces, " +
                    "directory infrastructure — was relying on this separation.\n\n" +
                    "Worth confirming what each one actually is before writing it up. A device " +
                    "at 192.168.100.1 is very often the cable modem behind the router rather " +
                    "than another segment of the same estate, which is a different finding with " +
                    "a different owner.",
                data = mapOf(
                    "source" to position.cidr,
                    "reached" to reached.joinToString { it.first.address },
                    "count" to reached.size.toString(),
                ),
            ),
        )
        return reached.size
    }

    // ------------------------------------------------------------- transport

    /** A TCP connect to a common port, which is a better liveness test than ICMP on filtered nets. */
    private fun isOpen(host: String, port: Int): Boolean = runCatching {
        Socket().use { socket ->
            socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
            socket.isConnected
        }
    }.getOrDefault(false)

    private fun respondsTo(host: String): Boolean = runCatching {
        InetAddress.getByName(host).isReachable(REACH_TIMEOUT_MS)
    }.getOrDefault(false) || LIVENESS_PORTS.any { isOpen(host, it) }

    /** One DNS question to a named resolver, which is what makes this a test of *that* resolver. */
    private suspend fun resolve(resolver: String, name: String, type: Int): String? =
        withContext(Dispatchers.IO) {
            withTimeoutOrNull(DNS_TIMEOUT_MS) {
                runCatching {
                    DatagramSocket().use { socket ->
                        socket.soTimeout = DNS_TIMEOUT_MS.toInt()
                        val query = Mdns.query(name, type, transactionId = TRANSACTION_ID)
                        socket.send(
                            DatagramPacket(
                                query,
                                query.size,
                                InetAddress.getByName(resolver),
                                DNS_PORT,
                            ),
                        )
                        val buffer = ByteArray(RESPONSE_BYTES)
                        val packet = DatagramPacket(buffer, buffer.size)
                        socket.receive(packet)
                        Mdns.parseResponse(buffer, packet.length)
                            .firstOrNull { it.target != null }
                            ?.target
                    }
                }.getOrNull()
            }
        }

    /** The DHCP search domain, where the platform will tell us one. */
    private fun searchDomain(position: NetworkPosition): String? =
        position.domain?.split(' ', ',')?.firstOrNull { it.isNotBlank() && it.contains('.') }

    private companion object {
        const val CONCURRENCY = 16
        const val CONNECT_TIMEOUT_MS = 700
        const val REACH_TIMEOUT_MS = 500
        const val DNS_TIMEOUT_MS = 2_000L
        const val DNS_PORT = 53
        const val RESPONSE_BYTES = 2048
        const val TRANSACTION_ID = 0x4D4F
        const val REVERSE_PROBES = 6
        const val REPORT_LIMIT = 12

        /**
         * Bounded because this runs against a live network and the point is a verdict on
         * isolation, not a census — host discovery already does the census properly.
         */
        const val PEER_LIMIT = 64

        val LIVENESS_PORTS = listOf(80, 443, 22)
        val CROSS_SEGMENT_PORTS = listOf(80, 443, 22, 23, 8080)
        val MANAGEMENT_PORTS = listOf(22, 23, 80, 443, 8080, 8443)
        val MANAGEMENT_PORTS_NAMES = mapOf(
            22 to "ssh", 23 to "telnet", 80 to "http", 443 to "https",
            8080 to "http-alt", 8443 to "https-alt",
        )
    }
}
