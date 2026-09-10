package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.modules.tier0.ApObservation
import dev.cyphernova.mobileops.modules.tier0.ApSecurityAnalyser
import dev.cyphernova.mobileops.modules.tier0.Encryption
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ApSecurityAnalyserTest {

    private fun ap(capabilities: String, ssid: String = "Test", frequency: Int = 2437) =
        ApObservation(
            ssid = ssid,
            bssid = "AA:BB:CC:DD:EE:FF",
            capabilities = capabilities,
            frequencyMhz = frequency,
            rssiDbm = -50,
        )

    @Test
    fun `open network is flagged high`() {
        val profile = ApSecurityAnalyser.analyse(ap("[ESS]"))
        assertEquals(Encryption.OPEN, profile.encryption)
        assertTrue(profile.issues.any { it.severity == Severity.HIGH })
    }

    @Test
    fun `wep is critical`() {
        val profile = ApSecurityAnalyser.analyse(ap("[WEP][ESS]"))
        assertEquals(Encryption.WEP, profile.encryption)
        assertTrue(profile.issues.any { it.severity == Severity.CRITICAL })
    }

    @Test
    fun `wpa3 sae is clean when pmf is on`() {
        val profile = ApSecurityAnalyser.analyse(ap("[RSN-SAE-CCMP][ESS][MFPR][MFPC]"))
        assertEquals(Encryption.WPA3, profile.encryption)
        assertTrue(profile.managementFrameProtection)
        assertTrue(profile.issues.isEmpty())
    }

    @Test
    fun `wpa3 transition mode is flagged as a downgrade path`() {
        val profile = ApSecurityAnalyser.analyse(ap("[RSN-SAE+WPA2-PSK-CCMP][ESS][MFPC]"))
        assertEquals(Encryption.WPA3_TRANSITION, profile.encryption)
        assertTrue(profile.issues.any { it.title.contains("transition") })
    }

    @Test
    fun `wps is flagged independently of encryption strength`() {
        val profile = ApSecurityAnalyser.analyse(ap("[WPA2-PSK-CCMP][WPS][ESS][MFPC]"))
        assertEquals(Encryption.WPA2, profile.encryption)
        assertTrue(profile.wpsEnabled)
        assertTrue(profile.issues.any { it.title.contains("WPS") })
    }

    @Test
    fun `missing pmf is flagged on an encrypted network`() {
        val profile = ApSecurityAnalyser.analyse(ap("[WPA2-PSK-CCMP][ESS]"))
        assertFalse(profile.managementFrameProtection)
        assertTrue(profile.issues.any { it.title.contains("management frame") })
    }

    @Test
    fun `enterprise wpa2 is recognised`() {
        assertEquals(
            Encryption.WPA2_ENTERPRISE,
            ApSecurityAnalyser.analyse(ap("[WPA2-EAP-CCMP][ESS][MFPC]")).encryption,
        )
    }

    @Test
    fun `channel maths covers all three bands`() {
        assertEquals(6, ap("[ESS]", frequency = 2437).channel)
        assertEquals(14, ap("[ESS]", frequency = 2484).channel)
        assertEquals(36, ap("[ESS]", frequency = 5180).channel)
        assertEquals(1, ap("[ESS]", frequency = 5955).channel)
    }

    @Test
    fun `band labels follow the frequency`() {
        assertEquals("2.4 GHz", ap("[ESS]", frequency = 2437).band)
        assertEquals("5 GHz", ap("[ESS]", frequency = 5180).band)
        assertEquals("6 GHz", ap("[ESS]", frequency = 6135).band)
    }

    @Test
    fun `hidden ssid is reported as informational only`() {
        val profile = ApSecurityAnalyser.analyse(ap("[RSN-SAE-CCMP][ESS][MFPR]", ssid = ""))
        assertTrue(profile.issues.any { it.severity == Severity.INFO && it.title.contains("Hidden") })
    }
}
