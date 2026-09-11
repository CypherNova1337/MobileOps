package dev.cyphernova.mobileops.modules.tier0

import android.os.Build
import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.capture.CaptureController
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleCategory
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule
import dev.cyphernova.mobileops.core.tls.CertificateAuthority
import dev.cyphernova.mobileops.core.tls.InterceptController
import dev.cyphernova.mobileops.core.tls.TrustStore
import java.io.File
import java.security.MessageDigest

/**
 * Arms TLS interception and manages the local certificate authority.
 *
 * Toggling this on does nothing to traffic on its own — the device has to be told to trust the
 * CA first, which is a deliberate act by the operator. That is TLS behaving correctly: a
 * substituted certificate is refused until someone with control of the device installs the
 * trust anchor.
 */
class TlsInterceptModule : PentestModule {
    override val id = "t0.tls.intercept"
    override val title = "TLS interception"
    override val description =
        "Terminates TLS locally so requests can be read in the clear, using a CA generated on this " +
            "device. Requires installing that CA. Run again to disarm."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.PASSIVE
    override val category = ModuleCategory.TRAFFIC

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        if (InterceptController.isEnabled) {
            InterceptController.setEnabled(false)
            val counters = InterceptController.counters.value
            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    severity = Severity.INFO,
                    title = "TLS interception disarmed",
                    subject = "interception",
                    detail = "Intercepted ${counters["tls_flows_intercepted"] ?: 0} flow(s), " +
                        "read ${counters["tls_requests_seen"] ?: 0} request(s), " +
                        "${counters["tls_handshake_refused"] ?: 0} client(s) refused the substituted " +
                        "certificate. Restart the capture for this to take effect on new flows.",
                    data = counters.mapValues { it.value.toString() },
                ),
            )
            return ModuleOutcome.Completed("Interception disarmed.")
        }

        val authority = CertificateAuthority(File(context.androidContext.filesDir, "tls"))
        val certificate = runCatching { authority.initialise() }.getOrElse {
            return ModuleOutcome.Failed("Could not create the local CA: ${it.message}")
        }

        val fingerprint = MessageDigest.getInstance("SHA-256")
            .digest(certificate.encoded)
            .joinToString(":") { "%02X".format(it) }
        InterceptController.setFingerprint(fingerprint)
        InterceptController.setEnabled(true)

        emit(
            Finding(
                moduleId = id,
                observedAtEpochMs = System.currentTimeMillis(),
                severity = Severity.INFO,
                title = "TLS interception armed",
                subject = CertificateAuthority.CA_COMMON_NAME,
                detail = trustLine(certificate) +
                    "Tap 'Install CA' on this card to hand it straight to the " +
                    "system certificate installer. If the installer sends you to Settings instead, " +
                    "the PEM is at ${authority.exportedCertificateFile.absolutePath} and can be " +
                    "shared from the Evidence tab.\n\n" +
                    trustStoreNote(authority),
                data = mapOf(
                    "ca_trusted" to TrustStore.status(certificate).trusted.toString(),
                    "ca_copies_installed" to TrustStore.status(certificate).copies.toString(),
                    "ca_sha256" to fingerprint,
                    "ca_pem_path" to authority.exportedCertificateFile.absolutePath,
                    "system_store_filename" to (authority.systemTrustStoreName() ?: ""),
                    "valid_until" to certificate.notAfter.toString(),
                ),
            ),
        )

        val note = if (CaptureController.isRunning) {
            " Stop and restart the capture to divert new flows through it."
        } else {
            " Start a capture to begin intercepting."
        }
        return ModuleOutcome.Completed("Interception armed; install the CA.$note")
    }

    /** Leads with where the CA stands, because an untrusted CA is why interception sees nothing. */
    private fun trustLine(certificate: java.security.cert.X509Certificate): String {
        val status = TrustStore.status(certificate)
        return when {
            status.hasStaleCopies ->
                "This CA is trusted, but ${status.copies} entries with its name are installed — " +
                    "older ones left behind. Remove the extras under Settings → Security → " +
                    "Trusted credentials → User. "
            status.trusted -> "This CA is already installed and trusted; no need to install it again. "
            else -> "This CA is not yet trusted by the device, so every handshake will be refused " +
                "until it is installed. "
        }
    }

    /**
     * The Android 7 change is the single thing that decides what this can see, so it is stated
     * up front rather than left for the operator to discover from an empty request list.
     */
    private fun trustStoreNote(authority: CertificateAuthority): String = buildString {
        append(
            "Since Android 7, apps trust user-installed CAs only if they opt in, so a " +
                "user-installed CA covers browsers and little else. ",
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            append(
                "To reach other apps the CA has to go in the system store, which needs root: " +
                    "copy the PEM to /system/etc/security/cacerts/",
            )
            append(authority.systemTrustStoreName() ?: "<hash>.0")
            append(" with mode 644. Certificate-pinning apps refuse either way, by design.")
        }
    }
}
