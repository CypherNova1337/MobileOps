package dev.cyphernova.mobileops.modules.tier0

import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleCategory
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetSocketAddress
import java.net.Socket

/**
 * TCP connect scan against the selected hosts, with a short banner grab on the ports that answer.
 *
 * A connect scan completes the three-way handshake, so it is loud and lands in the target's
 * logs — that is a property of doing this without root, not an oversight. SYN scanning needs
 * raw sockets, which means Tier 1.
 */
class PortScanModule : PentestModule {
    override val id = "t0.net.portscan"
    override val title = "TCP service scan"
    override val description =
        "Connect-scans a well-known port set on the selected hosts and grabs service banners. " +
            "Full-handshake scanning is logged by the target; SYN scanning requires Tier 1."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.ACTIVE
    override val category = ModuleCategory.NETWORK
    override val requiresTarget = true

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val targets = context.targets.hosts()
        if (targets.isEmpty()) {
            return ModuleOutcome.Blocked("No hosts selected. Pick targets on the Targets tab.")
        }

        var openCount = 0

        targets.forEach { host ->
            val open = coroutineScope {
                SERVICE_PORTS.keys.chunked(CONCURRENCY).flatMap { batch ->
                    batch.map { port -> async(Dispatchers.IO) { scanPort(host, port) } }.awaitAll()
                }.filterNotNull()
            }
            openCount += open.size

            open.forEach { result ->
                val service = SERVICE_PORTS[result.port].orEmpty()
                emit(
                    Finding(
                        moduleId = id,
                        observedAtEpochMs = System.currentTimeMillis(),
                        severity = severityFor(result.port),
                        title = "$host:${result.port} open ($service)",
                        subject = "$host:${result.port}",
                        detail = buildString {
                            append("TCP connect succeeded in ${result.latencyMs} ms.")
                            if (result.banner.isNotBlank()) {
                                append(" Banner: ${result.banner.take(BANNER_CHARS)}")
                            }
                            noteFor(result.port)?.let { append(" $it") }
                        },
                        data = mapOf(
                            "port" to result.port.toString(),
                            "service" to service,
                            "latency_ms" to result.latencyMs.toString(),
                            "banner" to result.banner.take(BANNER_CHARS),
                        ),
                    ),
                )
            }
        }

        return ModuleOutcome.Completed("$openCount open port(s) across ${targets.size} host(s).")
    }

    private data class OpenPort(val port: Int, val latencyMs: Long, val banner: String)

    private suspend fun scanPort(host: String, port: Int): OpenPort? = withContext(Dispatchers.IO) {
        val started = System.currentTimeMillis()
        runCatching {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
                val latency = System.currentTimeMillis() - started
                OpenPort(port, latency, grabBanner(socket))
            }
        }.getOrNull()
    }

    /**
     * Reads whatever the service volunteers on connect. Chatty protocols (SSH, SMTP, FTP) greet
     * first; anything that waits for a request just times out, which is why this is bounded and
     * failure-tolerant rather than protocol-aware.
     */
    private suspend fun grabBanner(socket: Socket): String =
        withTimeoutOrNull(BANNER_TIMEOUT_MS) {
            runCatching {
                socket.soTimeout = BANNER_TIMEOUT_MS.toInt()
                val buffer = ByteArray(BANNER_BYTES)
                val read = socket.getInputStream().read(buffer)
                if (read > 0) String(buffer, 0, read).trim().replace(Regex("[^\\x20-\\x7E]"), ".") else ""
            }.getOrDefault("")
        }.orEmpty()

    /** Cleartext and remote-admin services are worth a reviewer's attention on their own. */
    private fun severityFor(port: Int): Severity = when (port) {
        23, 21, 512, 513, 514 -> Severity.HIGH
        3389, 445, 139, 5900 -> Severity.MEDIUM
        80, 8080, 8000 -> Severity.LOW
        else -> Severity.INFO
    }

    private fun noteFor(port: Int): String? = when (port) {
        23 -> "Telnet transmits credentials in cleartext."
        21 -> "FTP transmits credentials in cleartext unless FTPS is enforced."
        445, 139 -> "SMB exposed on the LAN; confirm signing is required and v1 is disabled."
        3389 -> "RDP exposed; confirm NLA is required."
        5900 -> "VNC often ships without transport encryption."
        80, 8080, 8000 -> "Cleartext HTTP; confirm whether it redirects to TLS."
        else -> null
    }

    private companion object {
        const val CONNECT_TIMEOUT_MS = 600
        const val BANNER_TIMEOUT_MS = 800L
        const val BANNER_BYTES = 256
        const val BANNER_CHARS = 200
        const val CONCURRENCY = 32

        val SERVICE_PORTS = mapOf(
            21 to "ftp", 22 to "ssh", 23 to "telnet", 25 to "smtp", 53 to "dns",
            80 to "http", 110 to "pop3", 111 to "rpcbind", 135 to "msrpc", 139 to "netbios-ssn",
            143 to "imap", 443 to "https", 445 to "microsoft-ds", 465 to "smtps", 587 to "submission",
            631 to "ipp", 993 to "imaps", 995 to "pop3s", 1433 to "mssql", 1723 to "pptp",
            3000 to "http-alt", 3306 to "mysql", 3389 to "rdp", 5432 to "postgresql", 5900 to "vnc",
            6379 to "redis", 8000 to "http-alt", 8080 to "http-proxy", 8443 to "https-alt",
            9100 to "jetdirect", 27017 to "mongodb",
        )
    }
}
