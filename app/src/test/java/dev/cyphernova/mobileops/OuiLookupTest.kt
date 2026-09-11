package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.beacon.OuiLookup
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class OuiLookupTest {

    @Test
    fun `identifies a vendor from the bssid prefix`() {
        // Confirmed against a live Netgear RAX42 during testing.
        assertEquals("Netgear", OuiLookup.vendorOf("80:cc:9c:13:18:c4"))
        assertEquals("Ubiquiti", OuiLookup.vendorOf("24:A4:3C:11:22:33"))
    }

    @Test
    fun `case and separator do not matter`() {
        assertEquals("Netgear", OuiLookup.vendorOf("80CC9C131 8C4".replace(" ", "")))
        assertEquals("Netgear", OuiLookup.vendorOf("80-CC-9C-13-18-C4"))
        assertEquals("Netgear", OuiLookup.vendorOf("80:CC:9C:13:18:C4"))
    }

    @Test
    fun `an unlisted prefix is unknown rather than guessed`() {
        // AC:DE:48 is globally administered and not in the table, so it must read as unknown.
        // (AA:BB:CC would not do: 0xAA has the local bit set, making it a different case.)
        assertNull(OuiLookup.vendorOf("AC:DE:48:11:22:33"))
        assertEquals("unknown vendor", OuiLookup.describe("AC:DE:48:11:22:33"))
    }

    @Test
    fun `detects a locally administered address`() {
        // Bit 1 of the first octet set means the address belongs to no vendor.
        assertTrue(OuiLookup.isLocallyAdministered("02:00:00:00:00:00"))
        assertTrue(OuiLookup.isLocallyAdministered("DA:BB:CC:DD:EE:FF"))
        assertFalse(OuiLookup.isLocallyAdministered("80:CC:9C:13:18:C4"))
    }

    @Test
    fun `a randomised bssid is described as such rather than as a vendor`() {
        // On an access point this is abnormal, so it must not be hidden behind a vendor name.
        assertTrue(OuiLookup.describe("02:CC:9C:13:18:C4").contains("locally administered"))
    }

    @Test
    fun `malformed input does not throw`() {
        assertNull(OuiLookup.vendorOf(""))
        assertNull(OuiLookup.vendorOf("80:CC"))
        assertFalse(OuiLookup.isLocallyAdministered(""))
    }
}
