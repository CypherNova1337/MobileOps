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
        assertTrue(SsidIntel.classify("Smith Family Home").any { it.label.contains("Personal") })
        // A factory name splits into words too, and must not be read as somebody's name.
        assertFalse(SsidIntel.classify("SpectrumSetup-4C").any { it.label.contains("Personal") })
        assertFalse(SsidIntel.classify("VoidSec").any { it.label.contains("Personal") })
    }

    /**
     * Both of these were reported as household names in a live run. A word next to a serial is
     * how every ISP names a gateway, and it takes two letters-only words to look like a person.
     */
    @Test
    fun `a carrier gateway is not mistaken for a household name`() {
        listOf("TMOBILE-5271", "MyAltice 0234a3", "Optimum-A7F2", "VoidSec -5G").forEach { ssid ->
            assertFalse(ssid, SsidIntel.classify(ssid).any { it.label.contains("Personal") })
        }
    }

    @Test
    fun `carrier gateways are recognised as factory defaults instead`() {
        assertEquals("T-Mobile", SsidIntel.vendorFromSsid("TMOBILE-5271"))
        assertEquals("Altice", SsidIntel.vendorFromSsid("MyAltice 0234a3"))
        assertTrue(SsidIntel.isFactoryDefault("TMOBILE-5271"))
    }

    /** A brand word beside a real word is branding, not somebody's name. */
    @Test
    fun `a vendor word next to a real word is not a personal name`() {
        assertFalse(SsidIntel.classify("Netgear Upstairs").any { it.label.contains("Personal") })
        assertFalse(SsidIntel.classify("Guest Network").any { it.label.contains("Personal") })
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
