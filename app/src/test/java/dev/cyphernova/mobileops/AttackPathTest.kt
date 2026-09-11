package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.attack.AttackPath
import dev.cyphernova.mobileops.core.attack.AttackPath.Viability
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AttackPathTest {

    private fun target(
        open: Boolean = false,
        psk: Boolean = true,
        saeOnly: Boolean = false,
        enterprise: Boolean = false,
        wps: Boolean = false,
        wpsLocked: Boolean? = null,
        pushButton: Boolean = false,
        pmfRequired: Boolean = false,
        factorySsid: Boolean = false,
        haveCapture: Boolean = false,
        haveLan: Boolean = false,
    ) = AttackPath.Target(
        ssid = "VoidSec",
        bssid = "80:CC:9C:13:18:C4",
        isOpen = open,
        isWep = false,
        hasPresharedKey = psk,
        isSaeOnly = saeOnly,
        isEnterprise = enterprise,
        wpsAdvertised = wps,
        wpsPinLocked = wpsLocked,
        wpsPushButtonActive = pushButton,
        managementFrameProtectionRequired = pmfRequired,
        factoryDefaultSsid = factorySsid,
        haveCapture = haveCapture,
        haveLanAccess = haveLan,
    )

    private fun route(t: AttackPath.Target, name: String) =
        AttackPath.routesFor(t).first { it.name == name }

    @Test
    fun `an open network is reachable with nothing at all`() {
        val routes = AttackPath.routesFor(target(open = true, psk = false))
        assertEquals(Viability.OPEN, routes.first().viability)
        assertEquals("Join directly", routes.first().name)
        assertEquals("t0.wifi.join", routes.first().module)
    }

    @Test
    fun `an encrypted network has no direct join route`() {
        assertEquals(Viability.NOT_APPLICABLE, route(target(), "Join directly").viability)
    }

    /** Routes are ordered so the operator reads the cheapest first. */
    @Test
    fun `routes are sorted by how close they are to working`() {
        val routes = AttackPath.routesFor(target(wps = true, factorySsid = true))
        val ranks = routes.map { it.viability.rank }
        assertEquals(ranks.sorted(), ranks)
    }

    @Test
    fun `a psk network needs a capture before it can be cracked`() {
        val withoutCapture = route(target(), "Offline passphrase recovery")
        assertEquals(Viability.NEEDS_CAPTURE, withoutCapture.viability)
        assertNotNull(withoutCapture.requires)
        assertTrue(withoutCapture.requires!!.contains("monitor mode"))

        val withCapture = route(target(haveCapture = true), "Offline passphrase recovery")
        assertEquals(Viability.OPEN, withCapture.viability)
        assertEquals("t0.crack.handshake", withCapture.module)
    }

    /**
     * The single most important distinction in the analysis. SAE is a password-authenticated key
     * exchange, so a captured handshake cannot be tested offline — calling it crackable would
     * send an operator after something that cannot work.
     */
    @Test
    fun `sae-only defeats offline recovery, and transition mode does not`() {
        val saeOnly = route(target(saeOnly = true, psk = false), "Offline passphrase recovery")
        assertEquals(Viability.NOT_APPLICABLE, saeOnly.viability)
        assertTrue(saeOnly.rationale.contains("password-authenticated key exchange"))

        // Transition mode still offers PSK alongside SAE, so it remains a passphrase target.
        val transition = route(target(saeOnly = false, psk = true), "Offline passphrase recovery")
        assertEquals(Viability.NEEDS_CAPTURE, transition.viability)
        assertTrue(transition.rationale.contains("transition mode"))
    }

    @Test
    fun `pmkid follows the same applicability as the passphrase and is called out as cheaper`() {
        assertEquals(Viability.NEEDS_CAPTURE, route(target(), "PMKID recovery").viability)
        assertEquals(
            Viability.NOT_APPLICABLE,
            route(target(saeOnly = true, psk = false), "PMKID recovery").viability,
        )
        assertTrue(route(target(), "PMKID recovery").rationale.contains("no legitimate client"))
    }

    @Test
    fun `enterprise networks have no passphrase to recover`() {
        val enterprise = route(
            target(psk = false, enterprise = true),
            "Offline passphrase recovery",
        )
        assertEquals(Viability.NOT_APPLICABLE, enterprise.viability)
        assertTrue(enterprise.rationale.contains("802.1X"))
    }

    /** The registrar is an IP attack, so it is a pivot rather than a way through the front door. */
    @Test
    fun `the upnp registrar needs lan access before it is open`() {
        val offNetwork = route(target(wps = true), "WPS External Registrar over UPnP")
        assertEquals(Viability.NEEDS_ACCESS, offNetwork.viability)
        assertTrue(offNetwork.requires!!.contains("IP on this network"))

        val onNetwork = route(target(wps = true, haveLan = true), "WPS External Registrar over UPnP")
        assertEquals(Viability.OPEN, onNetwork.viability)
        assertEquals("t0.exploit.wpsregistrar", onNetwork.module)
    }

    @Test
    fun `a radio-side pin lock does not rule the upnp route out`() {
        val locked = route(target(wps = true, wpsLocked = true), "WPS External Registrar over UPnP")
        assertEquals(Viability.NEEDS_ACCESS, locked.viability)
        assertTrue(locked.rationale.contains("different code path"))

        val unknown = route(target(wps = true), "WPS External Registrar over UPnP")
        assertTrue(unknown.rationale.contains("does not carry the lock state"))
    }

    @Test
    fun `no wps means no wps routes`() {
        val routes = AttackPath.routesFor(target(wps = false))
        listOf("WPS External Registrar over UPnP", "WPS PIN over the air").forEach { name ->
            assertEquals(Viability.NOT_APPLICABLE, routes.first { it.name == name }.viability)
        }
    }

    /**
     * The removal of startWps in API 28 is the reason this is unreachable, and saying so is more
     * useful than omitting the route — it tells the operator what hardware changes the answer.
     */
    @Test
    fun `wps over the air is blocked with the reason attached`() {
        val overAir = route(target(wps = true), "WPS PIN over the air")
        assertEquals(Viability.BLOCKED, overAir.viability)
        assertTrue(overAir.rationale.contains("API 28"))
        assertTrue(overAir.requires!!.contains("injection"))
    }

    @Test
    fun `an active push-button session is an open door while it lasts`() {
        val active = route(target(wps = true, pushButton = true), "WPS push-button association")
        assertEquals(Viability.OPEN, active.viability)

        assertEquals(
            Viability.NOT_APPLICABLE,
            route(target(wps = true), "WPS push-button association").viability,
        )
    }

    /** Whether 802.11w is required decides whether a capture can be forced or has to be waited for. */
    @Test
    fun `pmf changes what capturing a handshake would take`() {
        val protected = route(target(pmfRequired = true), "Capture a handshake here")
        assertEquals(Viability.BLOCKED, protected.viability)
        assertTrue(protected.rationale.contains("will not work against it"))

        val unprotected = route(target(pmfRequired = false), "Capture a handshake here")
        assertTrue(unprotected.rationale.contains("can be deauthenticated"))
    }

    @Test
    fun `evil twin is blocked because the platform owns the softap ssid`() {
        val evilTwin = route(target(), "Evil twin / karma")
        assertEquals(Viability.BLOCKED, evilTwin.viability)
        assertTrue(evilTwin.rationale.contains("VoidSec"))
        assertTrue(evilTwin.rationale.contains("picks the hotspot SSID"))
    }

    @Test
    fun `a factory ssid adds the default credentials route and nothing else does`() {
        assertTrue(
            AttackPath.routesFor(target(factorySsid = true))
                .any { it.name == "Default administrative credentials" },
        )
        assertFalse(
            AttackPath.routesFor(target(factorySsid = false))
                .any { it.name == "Default administrative credentials" },
        )
    }

    @Test
    fun `the verdict names the open route when there is one`() {
        val verdict = AttackPath.verdict(target(open = true, psk = false))
        assertTrue(verdict.contains("Reachable now"))
        assertTrue(verdict.contains("Join directly"))
    }

    /**
     * A verdict must never read as "this network is secure". Absence of a route from this
     * handset is a statement about the handset, and the wording has to say so.
     */
    @Test
    fun `a verdict with no open route points at the next cheapest rather than declaring safety`() {
        val verdict = AttackPath.verdict(target())
        assertTrue(verdict.contains("No route is open from this handset"))
        assertTrue(verdict.contains("Next cheapest"))
        assertTrue(verdict.contains("limits of this hardware, not of the target"))
        assertFalse(verdict.contains("secure"))
    }

    @Test
    fun `the verdict prefers lan access over a capture when both would work`() {
        // On the network already, with WPS: the registrar is open and needs nothing further.
        val verdict = AttackPath.verdict(target(wps = true, haveLan = true))
        assertTrue(verdict.contains("Reachable now"))
        assertTrue(verdict.contains("WPS External Registrar over UPnP"))
    }

    @Test
    fun `every route carries a rationale and a distinct name`() {
        val routes = AttackPath.routesFor(target(wps = true, factorySsid = true))
        assertEquals(routes.map { it.name }.distinct().size, routes.size)
        assertTrue(routes.all { it.rationale.isNotBlank() })
        // Anything not immediately usable has to say what it would take.
        assertTrue(
            routes.filter { it.viability in setOf(Viability.NEEDS_ACCESS, Viability.NEEDS_CAPTURE) }
                .all { it.requires != null },
        )
    }
}
