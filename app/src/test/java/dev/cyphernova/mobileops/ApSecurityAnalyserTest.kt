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

    /**
     * Android reports any AP that sets the privacy bit with no RSN or WPA element as `[WEP]`.
     * On a 5 GHz or HT-capable radio that cannot be what it is — WEP is not usable with those
     * data rates — so the verdict is corrected rather than reported as a critical finding.
     */
    @Test
    fun `privacy without rsn on a modern radio is not called wep`() {
        val fiveGhz = ApSecurityAnalyser.analyse(ap("[WEP][ESS]", frequency = 5765))
        assertEquals(Encryption.PRIVACY_NO_RSN, fiveGhz.encryption)
        assertTrue(fiveGhz.issues.none { it.severity == Severity.CRITICAL })
        assertTrue(fiveGhz.issues.any { it.title.contains("Privacy bit") })
    }

    @Test
    fun `ht capability rules out wep on 2 point 4 as well`() {
        val observation = ApObservation(
            ssid = "Backhaul",
            bssid = "62:45:B8:E9:50:73",
            capabilities = "[WEP][ESS]",
            frequencyMhz = 2437,
            rssiDbm = -60,
            // Element 45 is HT Capabilities; WEP is not permitted with 802.11n rates.
            informationElements = listOf(45 to ByteArray(26)),
        )
        assertEquals(Encryption.PRIVACY_NO_RSN, ApSecurityAnalyser.analyse(observation).encryption)
    }

    @Test
    fun `genuine legacy wep is still reported as critical`() {
        val legacy = ApSecurityAnalyser.analyse(ap("[WEP][ESS]", frequency = 2437))
        assertEquals(Encryption.WEP, legacy.encryption)
        assertTrue(legacy.issues.any { it.severity == Severity.CRITICAL })
    }

    /** A non-802.11i link has no management frame protection to be missing. */
    @Test
    fun `the pmf note is suppressed for a non-standard privacy link`() {
        val profile = ApSecurityAnalyser.analyse(ap("[WEP][ESS]", frequency = 5765))
        assertTrue(profile.issues.none { it.title.contains("management frame") })
    }

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

class RssiReportingTest {

    private fun ap(rssi: Int) = ApObservation(
        ssid = "Test",
        bssid = "AA:BB:CC:DD:EE:FF",
        capabilities = "[WPA2-PSK-CCMP][ESS]",
        frequencyMhz = 2457,
        rssiDbm = rssi,
    )

    @Test
    fun `a real reading is reported in dBm`() {
        assertTrue(ap(-55).hasRssi)
        assertEquals("-55 dBm", ap(-55).rssiLabel)
    }

    @Test
    fun `zero is treated as withheld rather than a reading`() {
        // 0 dBm is a full milliwatt at the antenna. The platform uses it to mean "redacted",
        // and reporting it as a signal level is how a survey ends up lying.
        assertFalse(ap(0).hasRssi)
        assertEquals("signal withheld", ap(0).rssiLabel)
    }

    @Test
    fun `channel 10 resolves from its frequency`() {
        assertEquals(10, ap(-55).channel)
    }
}
