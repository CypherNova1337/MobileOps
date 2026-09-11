package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.attack.AttackPath
import dev.cyphernova.mobileops.core.attack.EnterpriseWifi
import dev.cyphernova.mobileops.core.attack.EnterpriseWifi.Level
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EnterpriseWifiTest {

    private fun posture(
        suites: Set<String> = setOf("802.1X"),
        enterprise: List<String> = listOf("aa:bb:cc:00:00:01"),
        personal: List<String> = emptyList(),
        pmfRequired: Boolean = false,
        pmfCapable: Boolean = false,
    ) = EnterpriseWifi.Posture(
        ssid = "CorpWiFi",
        akmSuites = suites,
        enterpriseBssids = enterprise,
        personalBssids = personal,
        managementFrameProtectionRequired = pmfRequired,
        managementFrameProtectionCapable = pmfCapable,
    )

    @Test
    fun `a network with no 802 1X radios produces nothing`() {
        val personal = posture(suites = setOf("PSK"), enterprise = emptyList())
        assertFalse(personal.isEnterprise)
        assertTrue(EnterpriseWifi.assess(personal).isEmpty())
        assertTrue(EnterpriseWifi.routesFor(personal).isEmpty())
    }

    /**
     * The exposure moved to the client rather than disappearing, and the assessment has to say
     * so — concluding an enterprise network is fine because there is no passphrase is backwards.
     */
    @Test
    fun `certificate validation is raised as the question that matters`() {
        val notes = EnterpriseWifi.assess(posture())
        val cert = notes.first { it.title.contains("certificate validation") }
        assertEquals(Level.HIGH, cert.severity)
        assertTrue(cert.detail.contains("MSCHAPv2"))
        // It is not observable from outside, so it must be stated as something to verify.
        assertTrue(cert.detail.contains("cannot test it"))
    }

    /** The finding worth walking a building for. */
    @Test
    fun `the same ssid served with a pre-shared key is critical`() {
        val mixed = posture(
            suites = setOf("802.1X", "PSK"),
            enterprise = listOf("aa:bb:cc:00:00:01"),
            personal = listOf("aa:bb:cc:00:00:02"),
        )
        assertTrue(mixed.hasPersonalFallback)

        val note = EnterpriseWifi.assess(mixed).first { it.title.contains("pre-shared key") }
        assertEquals(Level.CRITICAL, note.severity)
        assertTrue(note.detail.contains("aa:bb:cc:00:00:02"))
        assertTrue(note.detail.contains("bypassed"))
    }

    @Test
    fun `a consistent enterprise deployment raises no fallback note`() {
        assertFalse(posture().hasPersonalFallback)
        assertFalse(EnterpriseWifi.assess(posture()).any { it.title.contains("pre-shared key") })
    }

    /**
     * PMF matters more here than on a personal network, because provoking a reassociation
     * produces a fresh EAP exchange to listen to.
     */
    @Test
    fun `missing management frame protection is graded by whether it is even offered`() {
        val absent = EnterpriseWifi.assess(posture(pmfCapable = false))
            .first { it.title.contains("management frame") }
        assertEquals(Level.HIGH, absent.severity)

        val optional = EnterpriseWifi.assess(posture(pmfCapable = true))
            .first { it.title.contains("802.11w") }
        assertEquals(Level.MEDIUM, optional.severity)

        assertFalse(
            EnterpriseWifi.assess(posture(pmfRequired = true))
                .any { it.title.contains("management frame") || it.title.contains("802.11w") },
        )
    }

    @Test
    fun `suite b is recognised and softens the client-side note`() {
        val suiteB = posture(suites = setOf("802.1X-SuiteB-192"), pmfRequired = true)
        assertTrue(suiteB.isSuiteB)

        val notes = EnterpriseWifi.assess(suiteB)
        assertTrue(notes.any { it.title.contains("Suite B") })
        assertEquals(
            Level.LOW,
            notes.first { it.title.contains("certificate validation") }.severity,
        )
    }

    @Test
    fun `the rogue radius route is reported as blocked with what it would take`() {
        val route = EnterpriseWifi.routesFor(posture()).first { it.name.contains("Rogue RADIUS") }
        assertEquals(AttackPath.Viability.BLOCKED, route.viability)
        assertTrue(route.requires!!.contains("hostapd-wpe"))
        // Saying it is practical elsewhere is the useful part.
        assertTrue(route.rationale.contains("entirely practical"))
    }

    @Test
    fun `identity harvesting reflects whether reassociations can be provoked`() {
        val unprotected = EnterpriseWifi.routesFor(posture(pmfRequired = false))
            .first { it.name.contains("identity harvesting") }
        assertTrue(unprotected.rationale.contains("deauthenticated"))

        val protected = EnterpriseWifi.routesFor(posture(pmfRequired = true))
            .first { it.name.contains("identity harvesting") }
        assertTrue(protected.rationale.contains("cannot be provoked"))
    }

    @Test
    fun `a pre-shared key radio becomes a real route around the infrastructure`() {
        val mixed = posture(personal = listOf("aa:bb:cc:00:00:02"))
        val route = EnterpriseWifi.routesFor(mixed).first { it.name.contains("pre-shared key") }
        assertEquals(AttackPath.Viability.NEEDS_CAPTURE, route.viability)
        assertEquals("t0.crack.handshake", route.module)

        assertFalse(
            EnterpriseWifi.routesFor(posture()).any { it.name.contains("Associate to the pre-shared") },
        )
    }

    @Test
    fun `every note and route carries usable text`() {
        val mixed = posture(suites = setOf("802.1X", "PSK"), personal = listOf("aa:bb:cc:00:00:02"))
        assertTrue(EnterpriseWifi.assess(mixed).all { it.title.isNotBlank() && it.detail.isNotBlank() })
        assertTrue(EnterpriseWifi.routesFor(mixed).all { it.rationale.isNotBlank() })
    }
}
