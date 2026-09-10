package dev.cyphernova.mobileops.modules.tier0

import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.module.Intrusiveness
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

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val position = LocalNetwork.position(context.androidContext)
            ?: return ModuleOutcome.Failed("No active IPv4 network.")

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

        live.forEach { host ->
            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    severity = Severity.INFO,
                    title = "Live host ${host.address}",
                    subject = host.address,
                    detail = "Responded via ${host.method}." +
                        (host.hostname?.let { " Reverse DNS: $it." } ?: "") +
                        host.openPorts.takeIf { it.isNotEmpty() }
                            ?.let { " Answering on ${it.joinToString()}." }.orEmpty(),
                    data = mapOf(
                        "method" to host.method,
                        "hostname" to host.hostname.orEmpty(),
                        "open_ports" to host.openPorts.joinToString(),
                    ),
                ),
            )
        }

        return ModuleOutcome.Completed("${live.size} live host(s) of ${candidates.size} probed.")
    }

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
