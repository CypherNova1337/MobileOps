package dev.cyphernova.mobileops.core.tls

import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * A TLS context that completes a handshake in order to look at the certificate.
 *
 * The distinction this draws is the whole point of it. A client validates a certificate to decide
 * whether to *trust* a server with its data. An auditor completes the handshake to *examine* what
 * the server presented — and on a LAN appliance the certificate is almost always self-signed, so
 * a validating client throws before it can see the thing it came to look at.
 *
 * That is not a theoretical concern. The TLS audit ran with the default validating factory and
 * reported "handshake failed" against every host on a live network, which is to say it never
 * audited a single certificate on the entire class of device it exists to audit, and its findings
 * for legacy protocols, weak signatures, self-signed issuers and expiry were unreachable code.
 *
 * Validation failure is a finding here, not a reason to stop. Nothing is sent over these sockets;
 * they are opened, inspected and closed. Where this app acts as a client that carries data — the
 * upstream leg of the interception path — it validates properly, and that is a different object
 * in a different file.
 */
object InspectionTls {

    /** Accepts any chain so the handshake completes and the certificate can be read. */
    val socketFactory: SSLSocketFactory by lazy { context.socketFactory }

    val context: SSLContext by lazy {
        val acceptAll = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
        SSLContext.getInstance("TLS").apply {
            init(null, arrayOf<TrustManager>(acceptAll), SecureRandom())
        }
    }

    /**
     * Whether a chain would satisfy the platform's own trust store.
     *
     * Asked separately and on purpose: the handshake is completed permissively so the certificate
     * can be examined, and then this says whether a real client would have accepted it — which is
     * the finding, rather than something that stops the audit before it starts.
     */
    fun isTrustedByPlatform(chain: List<X509Certificate>): Boolean {
        if (chain.isEmpty()) return false
        return runCatching {
            val factory = javax.net.ssl.TrustManagerFactory
                .getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm())
                .apply { init(null as java.security.KeyStore?) }
            factory.trustManagers
                .filterIsInstance<X509TrustManager>()
                .firstOrNull()
                ?.also { it.checkServerTrusted(chain.toTypedArray(), "RSA") } != null
        }.getOrDefault(false)
    }
}
