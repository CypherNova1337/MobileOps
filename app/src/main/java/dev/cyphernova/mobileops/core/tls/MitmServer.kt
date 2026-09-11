package dev.cyphernova.mobileops.core.tls

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.Principal
import java.net.ServerSocket
import java.net.Socket
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.ExtendedSSLSession
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509ExtendedKeyManager

/** Counters for interception, kept separate from the relay's so each can be read on its own. */
class InterceptStats {
    val flowsIntercepted = AtomicLong()
    val handshakeRefused = AtomicLong()
    val upstreamFailed = AtomicLong()
    val requestsSeen = AtomicLong()
    val secretsSeen = AtomicLong()

    fun snapshot(): Map<String, Long> = mapOf(
        "tls_flows_intercepted" to flowsIntercepted.get(),
        "tls_handshake_refused" to handshakeRefused.get(),
        "tls_upstream_failed" to upstreamFailed.get(),
        "tls_requests_seen" to requestsSeen.get(),
        "tls_secrets_seen" to secretsSeen.get(),
    )
}

/**
 * Terminates TLS from the device, opens a second TLS connection to the real server, and relays
 * the plaintext between them so requests can be inspected.
 *
 * Running as a loopback listener rather than inside the packet relay is deliberate: the
 * device-facing side is then an ordinary [SSLSocket] and the platform does the TLS, instead of a
 * hand-rolled SSLEngine state machine stacked on the hand-rolled TCP one.
 *
 * The device only accepts the substituted certificate if it already trusts the local CA, which
 * is TLS working exactly as designed — interception requires the operator to have installed that
 * trust anchor deliberately. Since Android 7 an app trusts user-installed CAs only when it opts
 * in, so in practice this sees browser traffic; anything else needs the CA in the system store,
 * which is Tier 1. An app that pins its certificates refuses regardless, and that refusal is a
 * result worth recording rather than a fault to work around.
 */
class MitmServer(
    private val scope: CoroutineScope,
    private val authority: CertificateAuthority,
    private val protect: (Socket) -> Boolean,
    private val stats: InterceptStats,
    private val onExchange: (String, HttpExchange) -> Unit,
) {

    private var server: ServerSocket? = null

    val port: Int get() = server?.localPort ?: -1
    val isRunning: Boolean get() = server?.isClosed == false

    fun start(): Int {
        val socket = ServerSocket(0, BACKLOG, InetAddress.getByName(LOOPBACK))
        server = socket
        scope.launch(Dispatchers.IO) { acceptLoop(socket) }
        return socket.localPort
    }

    fun stop() {
        runCatching { server?.close() }
        server = null
        InterceptRegistry.clear()
    }

    private suspend fun acceptLoop(socket: ServerSocket) {
        while (scope.isActive && !socket.isClosed) {
            val client = runCatching { socket.accept() }.getOrNull() ?: break
            scope.launch(Dispatchers.IO) { handle(client) }
        }
    }

    private fun handle(client: Socket) {
        // The relay registered the real destination against this port before it connected.
        val destination = InterceptRegistry.claim(client.port)
        if (destination == null) {
            runCatching { client.close() }
            return
        }

        val chosenHost = AtomicReference<String?>(null)
        var upstream: SSLSocket? = null
        var deviceSide: SSLSocket? = null

        try {
            client.soTimeout = SOCKET_TIMEOUT_MS

            val context = SSLContext.getInstance("TLS").apply {
                init(
                    arrayOf(MintingKeyManager(authority, destination.ip, chosenHost)),
                    null,
                    SecureRandom(),
                )
            }

            deviceSide = (context.socketFactory as SSLSocketFactory)
                .createSocket(client, client.inetAddress.hostAddress, client.port, true) as SSLSocket
            deviceSide.useClientMode = false

            val handshook = runCatching { deviceSide.startHandshake() }.isSuccess
            if (!handshook) {
                // The client rejected the substituted certificate: either the CA is not trusted
                // (the Android 7 default) or the app pins. Both are the control working.
                stats.handshakeRefused.incrementAndGet()
                runCatching { deviceSide.close() }
                return
            }

            val host = chosenHost.get() ?: destination.ip

            upstream = connectUpstream(host, destination)
            if (upstream == null) {
                stats.upstreamFailed.incrementAndGet()
                runCatching { deviceSide.close() }
                return
            }

            stats.flowsIntercepted.incrementAndGet()
            relay(deviceSide, upstream, host)
        } catch (_: Exception) {
            stats.handshakeRefused.incrementAndGet()
        } finally {
            runCatching { client.close() }
            runCatching { upstream?.close() }
            runCatching { deviceSide?.close() }
        }
    }

    /**
     * The upstream leg verifies the real server properly, hostname included — which an
     * [SSLSocket] does not do by default. Skipping it would hide a genuine attack on the path
     * behind the interception being performed here.
     */
    private fun connectUpstream(host: String, destination: OriginalDestination): SSLSocket? =
        runCatching {
            val raw = Socket()
            protect(raw)
            raw.connect(InetSocketAddress(destination.ip, destination.port), SOCKET_TIMEOUT_MS)

            val socket = (SSLSocketFactory.getDefault() as SSLSocketFactory)
                .createSocket(raw, host, destination.port, true) as SSLSocket

            socket.soTimeout = SOCKET_TIMEOUT_MS
            socket.sslParameters = socket.sslParameters.apply {
                endpointIdentificationAlgorithm = "HTTPS"
                if (!host.matches(IPV4)) serverNames = listOf(SNIHostName(host))
            }
            socket.startHandshake()
            socket
        }.getOrNull()

    private fun relay(deviceSide: SSLSocket, upstream: SSLSocket, host: String) {
        val toUpstream = scope.launch(Dispatchers.IO) {
            val buffer = ByteArray(BUFFER_BYTES)
            var firstChunk = true
            runCatching {
                while (true) {
                    val read = deviceSide.inputStream.read(buffer)
                    if (read <= 0) break

                    // Only the opening chunk is parsed: that is where the request line and
                    // headers live, and buffering whole bodies would mean holding other
                    // people's data in memory for no analytical gain.
                    if (firstChunk) {
                        firstChunk = false
                        HttpPeek.parse(buffer, read)?.let { exchange ->
                            stats.requestsSeen.incrementAndGet()
                            stats.secretsSeen.addAndGet(exchange.secrets.size.toLong())
                            onExchange(host, exchange)
                        }
                    }

                    upstream.outputStream.write(buffer, 0, read)
                    upstream.outputStream.flush()
                }
            }
            runCatching { upstream.close() }
        }

        val buffer = ByteArray(BUFFER_BYTES)
        runCatching {
            while (true) {
                val read = upstream.inputStream.read(buffer)
                if (read <= 0) break
                deviceSide.outputStream.write(buffer, 0, read)
                deviceSide.outputStream.flush()
            }
        }
        toUpstream.cancel()
        runCatching { deviceSide.close() }
    }

    /**
     * Picks which certificate to present. The alias is the hostname itself, so whatever SNI the
     * client sent selects what it is given — the only way a substituted certificate can match
     * the name the client is checking.
     */
    private class MintingKeyManager(
        private val authority: CertificateAuthority,
        private val fallbackHost: String,
        private val chosenHost: AtomicReference<String?>,
    ) : X509ExtendedKeyManager() {

        override fun chooseServerAlias(
            keyType: String?,
            issuers: Array<Principal>?,
            socket: Socket?,
        ): String {
            val sni = (socket as? SSLSocket)?.handshakeSession?.let(::sniFrom)
            return (sni ?: fallbackHost).also { chosenHost.set(it) }
        }

        override fun chooseEngineServerAlias(
            keyType: String?,
            issuers: Array<Principal>?,
            engine: SSLEngine?,
        ): String {
            val sni = engine?.handshakeSession?.let(::sniFrom)
            return (sni ?: fallbackHost).also { chosenHost.set(it) }
        }

        private fun sniFrom(session: SSLSession): String? =
            (session as? ExtendedSSLSession)?.requestedServerNames
                ?.filterIsInstance<SNIHostName>()
                ?.firstOrNull()
                ?.asciiName

        override fun getCertificateChain(alias: String?): Array<X509Certificate>? {
            val host = alias ?: return null
            val leaf = authority.leafFor(host) ?: return null
            val ca = authority.certificate ?: return null
            return arrayOf(leaf.certificate, ca)
        }

        override fun getPrivateKey(alias: String?): PrivateKey? =
            alias?.let { authority.leafFor(it)?.privateKey }

        override fun getServerAliases(keyType: String?, issuers: Array<Principal>?): Array<String> =
            arrayOf(fallbackHost)

        override fun getClientAliases(keyType: String?, issuers: Array<Principal>?): Array<String>? = null

        override fun chooseClientAlias(
            keyType: Array<String>?,
            issuers: Array<Principal>?,
            socket: Socket?,
        ): String? = null
    }

    private companion object {
        const val LOOPBACK = "127.0.0.1"
        const val BACKLOG = 64
        const val BUFFER_BYTES = 16 * 1024
        const val SOCKET_TIMEOUT_MS = 30_000
        val IPV4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
    }
}
