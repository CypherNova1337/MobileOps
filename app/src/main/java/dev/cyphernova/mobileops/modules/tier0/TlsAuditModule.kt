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
import kotlinx.coroutines.withContext
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import dev.cyphernova.mobileops.core.tls.InspectionTls
import javax.net.ssl.SSLSocket

/**
 * Inspects the TLS a host actually negotiates: protocol version, cipher suite, certificate
 * validity and chain length. Handshakes only — no data is sent past the negotiation.
 */
class TlsAuditModule : PentestModule {
    override val id = "t0.tls.audit"
    override val title = "TLS / certificate audit"
    override val description =
        "Handshakes with the selected hosts and reports the negotiated protocol and cipher, certificate " +
            "expiry, self-signed chains and legacy signature algorithms."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.ACTIVE
    override val category = ModuleCategory.NETWORK
    override val requiresTarget = true

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        // A bare host is assumed to mean 443; an explicit endpoint keeps its own port.
        val targets = context.targets.endpoints(defaultPort = DEFAULT_TLS_PORT)
        if (targets.isEmpty()) {
            return ModuleOutcome.Blocked("No hosts selected. Pick targets on the Targets tab.")
        }

        var audited = 0

        targets.forEach { (host, port) ->
            val result = handshake(host, port)

            if (result == null) {
                emit(
                    Finding(
                        moduleId = id,
                        observedAtEpochMs = System.currentTimeMillis(),
                        severity = Severity.INFO,
                        title = "TLS handshake failed on $host:$port",
                        subject = "$host:$port",
                        detail = "No handshake completed. The certificate is not the reason — " +
                            "this audit accepts any chain. That leaves a closed port, plaintext " +
                            "on a TLS port, or a device refusing the protocols offered.",
                    ),
                )
                return@forEach
            }
            audited++

            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    severity = Severity.INFO,
                    title = "TLS on $host:$port — ${result.protocol}",
                    subject = "$host:$port",
                    detail = "Negotiated ${result.protocol} with ${result.cipherSuite}. " +
                        "Chain of ${result.chainLength}, leaf issued to ${result.subject} by ${result.issuer}.",
                    data = mapOf(
                        "protocol" to result.protocol,
                        "cipher_suite" to result.cipherSuite,
                        "subject" to result.subject,
                        "issuer" to result.issuer,
                        "expires_in_days" to result.daysUntilExpiry.toString(),
                        "signature_algorithm" to result.signatureAlgorithm,
                    ),
                ),
            )

            result.issues().forEach { issue ->
                emit(
                    Finding(
                        moduleId = id,
                        observedAtEpochMs = System.currentTimeMillis(),
                        severity = issue.severity,
                        title = "${issue.title} — $host:$port",
                        subject = "$host:$port",
                        detail = issue.detail,
                    ),
                )
            }
        }

        return ModuleOutcome.Completed("$audited of ${targets.size} target(s) completed a handshake.")
    }

    private data class TlsResult(
        val protocol: String,
        val cipherSuite: String,
        val subject: String,
        val issuer: String,
        val chainLength: Int,
        val daysUntilExpiry: Long,
        val signatureAlgorithm: String,
        val selfSigned: Boolean,
        /** Whether a real client, validating normally, would have accepted this chain. */
        val trustedByPlatform: Boolean,
    ) {
        fun issues(): List<SecurityIssue> = buildList {
            // Asked here rather than allowed to abort the handshake: a chain no client trusts is
            // the finding. On an admin interface it also trains everyone who uses it to click
            // through a certificate warning, which is what makes interception work later.
            if (!trustedByPlatform && !selfSigned) {
                add(
                    SecurityIssue(
                        Severity.MEDIUM,
                        "Certificate would be rejected by a normal client",
                        "The chain does not validate against the platform trust store, and it is " +
                            "not simply self-signed — an incomplete chain or an expired " +
                            "intermediate produces this. Every user of this interface is being " +
                            "taught to click through the warning.",
                    ),
                )
            }
            if (protocol in LEGACY_PROTOCOLS) {
                add(
                    SecurityIssue(
                        Severity.HIGH,
                        "Legacy TLS version negotiated",
                        "$protocol is deprecated (RFC 8996). Only TLS 1.2 and 1.3 should be offered.",
                    ),
                )
            }
            if (daysUntilExpiry < 0) {
                add(
                    SecurityIssue(
                        Severity.HIGH,
                        "Expired certificate",
                        "The leaf certificate expired ${-daysUntilExpiry} day(s) ago.",
                    ),
                )
            } else if (daysUntilExpiry < EXPIRY_WARN_DAYS) {
                add(
                    SecurityIssue(
                        Severity.LOW,
                        "Certificate expiring soon",
                        "The leaf certificate expires in $daysUntilExpiry day(s).",
                    ),
                )
            }
            if (selfSigned) {
                add(
                    SecurityIssue(
                        Severity.MEDIUM,
                        "Self-signed certificate",
                        "The leaf is its own issuer, so clients cannot distinguish it from an interception " +
                            "certificate without pinning.",
                    ),
                )
            }
            if (WEAK_SIGNATURES.any { signatureAlgorithm.contains(it, ignoreCase = true) }) {
                add(
                    SecurityIssue(
                        Severity.HIGH,
                        "Weak certificate signature",
                        "Signed with $signatureAlgorithm; SHA-1 and MD5 signatures are forgeable.",
                    ),
                )
            }
            if (cipherSuite.contains("_RC4_") || cipherSuite.contains("_3DES_") ||
                cipherSuite.contains("_NULL_") || cipherSuite.contains("_anon_")
            ) {
                add(
                    SecurityIssue(
                        Severity.HIGH,
                        "Weak cipher suite negotiated",
                        "$cipherSuite offers no meaningful confidentiality guarantee.",
                    ),
                )
            }
        }
    }

    /**
     * Completes a handshake in order to look at the certificate.
     *
     * The default factory validates, and a LAN appliance's certificate is self-signed, so it
     * threw on every host this module exists to audit — reporting "handshake failed" and leaving
     * the protocol, signature, expiry and self-signed findings below as unreachable code. The
     * handshake is completed permissively and whether a real client would have trusted the chain
     * is then asked separately, because that is the finding rather than a reason to stop.
     */
    private suspend fun handshake(host: String, port: Int): TlsResult? = withContext(Dispatchers.IO) {
        runCatching {
            val factory = InspectionTls.socketFactory
            (factory.createSocket() as SSLSocket).use { socket ->
                socket.soTimeout = HANDSHAKE_TIMEOUT_MS
                socket.connect(java.net.InetSocketAddress(host, port), HANDSHAKE_TIMEOUT_MS)
                socket.startHandshake()

                val session = socket.session
                val chain = session.peerCertificates.filterIsInstance<X509Certificate>()
                val leaf = chain.firstOrNull() ?: return@use null

                val msUntilExpiry = leaf.notAfter.time - System.currentTimeMillis()
                TlsResult(
                    protocol = session.protocol,
                    cipherSuite = session.cipherSuite,
                    subject = leaf.subjectX500Principal.name,
                    issuer = leaf.issuerX500Principal.name,
                    chainLength = chain.size,
                    daysUntilExpiry = TimeUnit.MILLISECONDS.toDays(msUntilExpiry),
                    signatureAlgorithm = leaf.sigAlgName,
                    selfSigned = leaf.subjectX500Principal == leaf.issuerX500Principal,
                    trustedByPlatform = InspectionTls.isTrustedByPlatform(chain),
                )
            }
        }.getOrNull()
    }

    private companion object {
        const val DEFAULT_TLS_PORT = 443
        const val HANDSHAKE_TIMEOUT_MS = 5_000
        const val EXPIRY_WARN_DAYS = 30L
        val LEGACY_PROTOCOLS = setOf("SSLv3", "TLSv1", "TLSv1.1")
        val WEAK_SIGNATURES = listOf("SHA1", "MD5", "MD2")
    }
}
