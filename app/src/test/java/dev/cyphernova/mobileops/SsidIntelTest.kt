package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.beacon.SsidIntel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SsidIntelTest {

    @Test
    fun `factory default names are recognised across vendors`() {
        listOf(
            "NETGEAR54" to "Netgear",
            "TP-Link_1A2B" to "TP-Link",
            "belkin.a7f" to "Belkin",
            "ATT4Gh2Kd" to "AT&T",
            "SpectrumSetup-4C" to "Spectrum",
            "HOME-A1B2" to "Comcast",
        ).forEach { (ssid, vendor) ->
            assertTrue("$ssid should be a factory default", SsidIntel.isFactoryDefault(ssid))
            assertEquals(vendor, SsidIntel.vendorFromSsid(ssid))
        }
    }

    @Test
    fun `a renamed network is not treated as a factory default`() {
        listOf("VoidSec", "The Lab", "coffee shop wifi").forEach { ssid ->
            assertFalse(ssid, SsidIntel.isFactoryDefault(ssid))
            assertNull(SsidIntel.vendorFromSsid(ssid))
        }
    }

    @Test
    fun `a factory default raises a concern rather than a note`() {
        val notes = SsidIntel.classify("NETGEAR54")
        assertTrue(notes.any { it.weight == SsidIntel.Weight.CONCERN })
    }

    @Test
    fun `a personal name is flagged but a serial-style name is not`() {
        assertTrue(SsidIntel.classify("Dave's House").any { it.label.contains("Personal") })
        assertTrue(SsidIntel.classify("Smith Family Network").any { it.label.contains("Personal") })
        // A factory name splits into words too, and must not be read as somebody's name.
        assertFalse(SsidIntel.classify("SpectrumSetup-4C").any { it.label.contains("Personal") })
        assertFalse(SsidIntel.classify("VoidSec").any { it.label.contains("Personal") })
    }

    @Test
    fun `device types are identified from the name`() {
        assertTrue(SsidIntel.classify("HP-Print-2C-Officejet").any { it.label.contains("Device type") })
        assertTrue(SsidIntel.classify("Sonos-Kitchen").any { it.label.contains("Device type") })
    }

    @Test
    fun `network roles disclosed in the name are picked up`() {
        assertTrue(SsidIntel.classify("Acme-Guest").any { it.label.contains("Network role") })
        assertTrue(SsidIntel.classify("CORP-WIFI").any { it.label.contains("Network role") })
        assertTrue(SsidIntel.classify("Store POS").any { it.label.contains("Network role") })
    }

    @Test
    fun `wifi direct advertisements are noted but not treated as weak defaults`() {
        val notes = SsidIntel.classify("DIRECT-a7-HP OfficeJet")
        assertTrue(notes.isNotEmpty())
        assertTrue(notes.first().detail.contains("Direct"))
    }

    @Test
    fun `a blank ssid produces nothing`() {
        assertTrue(SsidIntel.classify("").isEmpty())
        assertTrue(SsidIntel.classify("   ").isEmpty())
    }
}
