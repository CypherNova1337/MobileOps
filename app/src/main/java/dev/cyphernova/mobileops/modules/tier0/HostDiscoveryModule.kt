package dev.cyphernova.mobileops.modules.tier0

import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.iot.DeviceFingerprint
import dev.cyphernova.mobileops.core.iot.IotPorts
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleCategory
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule
import dev.cyphernova.mobileops.core.net.Cidr4
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Sweeps the attached subnet for live hosts. Whatever it finds becomes selectable on the Targets
 * tab, so this is usually the first thing run on a new network.
 */
class HostDiscoveryModule : PentestModule {
    override val id = "t0.net.discovery"
    override val title = "Subnet host discovery"
    override val description =
        "Sweeps the local subnet for reachable hosts using ICMP echo plus TCP connect probes on common " +
            "service ports. Discovered hosts become selectable targets."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.ACTIVE
    override val category = ModuleCategory.NETWORK

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val position = LocalNetwork.position(context.androidContext)
            ?: return ModuleOutcome.Failed("No active IPv4 network.")

        if (!position.hasLocalSubnet) {
            return ModuleOutcome.Blocked(
                "This device is on ${position.transport.label} with a /${position.prefixLength} " +
                    "address, which is a point-to-point link: there are no neighbours to find. " +
                    "LAN modules need WiFi or Ethernet. WiFi survey, traffic capture and TLS " +
                    "interception all still work here.",
            )
        }

        // A /16 sweep is 65k probes: minutes of radio time and a flat battery, not a useful scan.
        if (position.prefixLength < MIN_PREFIX) {
            return ModuleOutcome.Blocked(
                "Refusing to sweep a /${position.prefixLength}: that is ${1 shl (32 - position.prefixLength)} " +
                    "addresses and would take far too long. A /$MIN_PREFIX is the widest this sweeps.",
            )
        }

        val candidates = Cidr4.hosts(position.cidr, limit = MAX_HOSTS)
        if (candidates.isEmpty()) {
            return ModuleOutcome.Failed("Could not enumerate hosts for ${position.cidr}.")
        }

        emit(
            Finding(
                moduleId = id,
                observedAtEpochMs = System.currentTimeMillis(),
                severity = Severity.INFO,
                title = "Sweep started on ${position.cidr}",
                subject = position.cidr,
                detail = "${candidates.size} addresses to probe. Local address ${position.localAddress}, " +
                    "gateway ${position.gateway ?: "unknown"}, " +
                    "DNS ${position.dnsServers.joinToString().ifBlank { "unknown" }}.",
                data = mapOf(
                    "interface" to position.interfaceName.orEmpty(),
                    "candidates" to candidates.size.toString(),
                    "gateway" to position.gateway.orEmpty(),
                ),
            ),
        )

        val live = coroutineScope {
            candidates.chunked(CONCURRENCY).flatMap { batch ->
                batch.map { address -> async(Dispatchers.IO) { probe(address) } }.awaitAll()
            }.filterNotNull()
        }

        // One census rather than a finding per address. A sweep of a populated subnet produced
        // eleven separate notes saying nothing but "this answered", which buried the findings
        // that meant something — the inventory is one thing, so it reads as one thing.
        emit(censusFinding(position, live, candidates.size))

        // Anything the sweep could already put a name to gets one. The classifier exists and
        // was only wired to the IoT module, so a printer found here was reported as an address
        // with ports rather than as a printer.
        live.forEach { host ->
            val verdict = DeviceFingerprint.classify(
                DeviceFingerprint.Evidence(
                    address = host.address,
                    openPorts = host.openPorts.toSet(),
                    names = listOfNotNull(host.hostname),
                ),
            )
            if (verdict.category == DeviceFingerprint.Category.UNKNOWN) return@forEach
            if (verdict.category == DeviceFingerprint.Category.ENDPOINT && host.hostname == null) {
                return@forEach
            }
            emit(identifiedFinding(position, host, verdict))
        }

        return ModuleOutcome.Completed("${live.size} live host(s) of ${candidates.size} probed.")
    }

    /** The whole sweep as one inventory, which is how a reader wants to see it. */
    private fun censusFinding(
        position: NetworkPosition,
        live: List<LiveHost>,
        probed: Int,
    ) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.INFO,
        title = "${live.size} live host(s) on ${position.cidr}",
        subject = position.cidr,
        detail = buildString {
            append("${live.size} of $probed address(es) answered. ")
            append(
                live.joinToString("; ") { host ->
                    val role = when (host.address) {
                        position.localAddress -> " (this device)"
                        position.gateway -> " (gateway)"
                        else -> ""
                    }
                    buildString {
                        append(host.address).append(role)
                        host.hostname?.let { append(" [$it]") }
                        host.openPorts.takeIf { it.isNotEmpty() }
                            ?.let { append(" ports ${it.joinToString()}") }
                    }
                },
            )
            append(".")
        },
        data = mapOf(
            "cidr" to position.cidr,
            "probed" to probed.toString(),
            "live" to live.size.toString(),
            "addresses" to live.joinToString { it.address },
        ),
    )

    /**
     * A host the sweep could name. Reported separately from the census because what a thing *is*
     * decides what happens next — and on a site whose value is in its equipment, that is the
     * whole point of sweeping at all.
     */
    private fun identifiedFinding(
        position: NetworkPosition,
        host: LiveHost,
        verdict: DeviceFingerprint.Verdict,
    ) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = if (verdict.fragility == IotPorts.Fragility.FRAGILE) Severity.LOW else Severity.INFO,
        title = "${verdict.category.label} — ${host.address}",
        subject = host.address,
        detail = buildString {
            append("Identified as ${verdict.category.label} (${verdict.confidence.label}): ")
            append("${verdict.basis}. ")
            if (verdict.significance.isNotBlank()) append("${verdict.significance} ")
            if (verdict.fragility == IotPorts.Fragility.FRAGILE) {
                append("Handled as ${verdict.fragility.label} — use the IoT module, not a scanner.")
            } else {
                append("Run the IoT module against it for a firmer identification.")
            }
        },
        data = mapOf(
            "host" to host.address,
            "category" to verdict.category.name,
            "confidence" to verdict.confidence.name,
            "fragility" to verdict.fragility.name,
            "open_ports" to host.openPorts.joinToString(),
        ),
    )

    private data class LiveHost(
        val address: String,
        val method: String,
        val hostname: String?,
        val openPorts: List<Int>,
    )

    private suspend fun probe(address: String): LiveHost? = withContext(Dispatchers.IO) {
        val inet = runCatching { InetAddress.getByName(address) }.getOrNull() ?: return@withContext null

        // isReachable uses ICMP where the OS allows it and falls back to a TCP probe on port 7.
        // On Android it frequently returns false for hosts that are plainly up, so a negative
        // result is not treated as conclusive — we still try the service ports.
        val icmp = runCatching { inet.isReachable(ICMP_TIMEOUT_MS) }.getOrDefault(false)
        val open = COMMON_PORTS.filter { port -> tcpConnects(address, port) }

        when {
            open.isNotEmpty() -> LiveHost(
                address = address,
                method = if (icmp) "ICMP echo + TCP" else "TCP connect",
                hostname = reverseLookup(inet, address),
                openPorts = open,
            )
            icmp -> LiveHost(address, "ICMP echo", reverseLookup(inet, address), emptyList())
            else -> null
        }
    }

    private fun tcpConnects(address: String, port: Int): Boolean =
        runCatching {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(address, port), TCP_TIMEOUT_MS)
                true
            }
        }.getOrDefault(false)

    private fun reverseLookup(inet: InetAddress, address: String): String? =
        runCatching { inet.canonicalHostName.takeIf { it != address } }.getOrNull()

    private companion object {
        const val MIN_PREFIX = 22
        const val MAX_HOSTS = 1024
        const val CONCURRENCY = 64
        const val ICMP_TIMEOUT_MS = 400
        const val TCP_TIMEOUT_MS = 350

        /** A liveness fingerprint, not a service inventory — that is the port scanner's job. */
        val COMMON_PORTS = listOf(80, 443, 22, 445, 139, 8080, 53, 3389)
    }
}
