package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.tls.CertificateAuthority
import dev.cyphernova.mobileops.core.tls.TrustStatus
import dev.cyphernova.mobileops.core.tls.TrustStore
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class TrustStatusTest {

    @Test
    fun `a single trusted entry is not stale`() {
        val status = TrustStatus(trusted = true, copies = 1, aliases = listOf("user:1"))
        assertFalse(status.hasStaleCopies)
        assertTrue(status.userInstalled)
    }

    @Test
    fun `more than one entry with our name means copies were left behind`() {
        val status = TrustStatus(trusted = true, copies = 3, aliases = listOf("user:1", "user:2", "user:3"))
        assertTrue(status.hasStaleCopies)
    }

    @Test
    fun `a system anchor is not reported as user installed`() {
        val status = TrustStatus(trusted = true, copies = 1, aliases = listOf("system:abc"))
        assertFalse(status.userInstalled)
    }

    @Test
    fun `nothing installed is the safe default`() {
        assertFalse(TrustStatus.UNKNOWN.trusted)
        assertEquals(0, TrustStatus.UNKNOWN.copies)
        assertFalse(TrustStatus.UNKNOWN.hasStaleCopies)
    }
}

class TrustStoreDegradationTest {

    @get:Rule val folder = TemporaryFolder()

    @Test
    fun `reports not trusted rather than throwing where the store is absent`() = runBlocking {
        // AndroidCAStore only exists on a device. Off-device the lookup must degrade to "not
        // trusted" rather than throwing, or every caller has to guard it.
        val certificate = CertificateAuthority(folder.newFolder("tls")).initialise()
        val status = TrustStore.status(certificate)

        assertFalse(status.trusted)
        assertFalse(status.hasStaleCopies)
    }
}
