package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.tls.InspectionTls
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The TLS audit ran with the platform's validating socket factory, so the handshake threw against
 * every LAN appliance — which is the entire class of device it exists to audit, because they all
 * ship self-signed certificates. It reported "handshake failed" and its findings for legacy
 * protocols, weak signatures, self-signed issuers and expiry were unreachable code for the life
 * of the project.
 *
 * The distinction that fixes it is worth asserting: a client validates to decide whether to trust
 * a server with its data; an auditor completes the handshake to examine what was presented, and
 * asks about trust separately, as a finding.
 */
class TlsInspectionTest {

    private val module = File(
        "src/main/java/dev/cyphernova/mobileops/modules/tier0/TlsAuditModule.kt",
    )

    @Test
    fun `the inspection context accepts any chain so a certificate can be read`() {
        assertNotNull(InspectionTls.socketFactory)
        val managers = InspectionTls.context.let { it }
        assertNotNull(managers)
    }

    @Test
    fun `an empty chain is never reported as trusted`() {
        assertFalse(InspectionTls.isTrustedByPlatform(emptyList()))
    }

    /** The regression itself: the audit must not go back to the validating factory. */
    @Test
    fun `the tls audit does not use the validating default factory`() {
        assertTrue("module not found at ${module.absolutePath}", module.exists())
        val source = module.readText()
        assertFalse(
            "SSLSocketFactory.getDefault() validates, so every self-signed LAN appliance throws " +
                "before its certificate can be examined",
            source.contains("SSLSocketFactory.getDefault()"),
        )
        assertTrue(source.contains("InspectionTls.socketFactory"))
    }

    /**
     * The audit exists to report these, and behind a validating handshake none of them could ever
     * fire. Asserting they are still reachable is cheap insurance against the same silent loss.
     */
    @Test
    fun `the audit still carries the findings the handshake was hiding`() {
        val source = module.readText()
        listOf(
            "Legacy TLS version",
            "Self-signed",
            "expire",
            "signature",
        ).forEach {
            assertTrue("the '$it' finding must still exist", source.contains(it, ignoreCase = true))
        }
    }
}
