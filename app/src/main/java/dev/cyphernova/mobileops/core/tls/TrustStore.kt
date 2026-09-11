package dev.cyphernova.mobileops.core.tls

import java.security.KeyStore
import java.security.cert.X509Certificate

/** Where a CA stands with this device's trust store. */
data class TrustStatus(
    /** This exact certificate is trusted — byte for byte, not merely a namesake. */
    val trusted: Boolean,
    /** Entries sharing our CA's subject, which is how stale copies show up. */
    val copies: Int,
    val aliases: List<String>,
) {
    /** More than one entry with our name means earlier CAs were left behind. */
    val hasStaleCopies: Boolean get() = copies > 1

    /** Installed by the user rather than shipped with the system. */
    val userInstalled: Boolean get() = aliases.any { it.startsWith("user:") }

    companion object {
        val UNKNOWN = TrustStatus(trusted = false, copies = 0, aliases = emptyList())
    }
}

/**
 * Reads the device's trust store to find out whether the interception CA is already installed.
 *
 * `AndroidCAStore` exposes both the system anchors and anything the user has added, and reading
 * it needs no permission. That makes the install button honest: it can tell the difference
 * between "not installed", "installed", and "installed several times over", instead of firing
 * the installer again and hoping.
 *
 * An app cannot remove a user-installed CA — only the person holding the device can, through
 * Settings. So the useful thing to do about duplicates is report them precisely.
 */
object TrustStore {

    fun status(certificate: X509Certificate): TrustStatus = runCatching {
        val store = KeyStore.getInstance(ANDROID_CA_STORE).apply { load(null) }
        val ours = certificate.encoded
        val subject = certificate.subjectX500Principal

        var trusted = false
        val matching = mutableListOf<String>()

        store.aliases().toList().forEach { alias ->
            val candidate = runCatching { store.getCertificate(alias) as? X509Certificate }
                .getOrNull() ?: return@forEach

            // Match on subject to count copies, but only identical bytes count as trusted: a
            // regenerated CA shares the subject and would otherwise look already-installed.
            if (candidate.subjectX500Principal == subject) {
                matching += alias
                if (candidate.encoded.contentEquals(ours)) trusted = true
            }
        }

        TrustStatus(trusted = trusted, copies = matching.size, aliases = matching)
    }.getOrDefault(TrustStatus.UNKNOWN)

    private const val ANDROID_CA_STORE = "AndroidCAStore"
}
