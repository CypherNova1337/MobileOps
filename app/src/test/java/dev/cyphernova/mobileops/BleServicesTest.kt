package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.ble.BleServices
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BleServicesTest {

    @Test
    fun `standard services resolve to their names`() {
        // These four came off a live QCC3034 audio device during testing.
        assertEquals("Battery", BleServices.describe("0000180f-0000-1000-8000-00805f9b34fb"))
        assertEquals("Link Loss", BleServices.describe("00001803-0000-1000-8000-00805f9b34fb"))
        assertEquals("TX Power", BleServices.describe("00001804-0000-1000-8000-00805f9b34fb"))
        assertEquals("Immediate Alert", BleServices.describe("00001802-0000-1000-8000-00805f9b34fb"))
    }

    @Test
    fun `member services resolve too`() {
        assertEquals("LG Electronics", BleServices.describe("0000feb9-0000-1000-8000-00805f9b34fb"))
        assertEquals("Eddystone beacon", BleServices.describe("0000feaa-0000-1000-8000-00805f9b34fb"))
    }

    @Test
    fun `an unlisted short service is reported by number rather than guessed`() {
        assertEquals("service 0x18FF", BleServices.describe("000018ff-0000-1000-8000-00805f9b34fb"))
    }

    @Test
    fun `a custom uuid is not forced into the sig numbering`() {
        val custom = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
        assertNull(BleServices.shortIdOf(custom))
        assertTrue(BleServices.describe(custom).startsWith("custom service"))
    }

    @Test
    fun `case does not matter`() {
        assertEquals(0x180F, BleServices.shortIdOf("0000180F-0000-1000-8000-00805F9B34FB"))
    }

    /** These are the services that say what a device will do for whoever connects. */
    @Test
    fun `services worth a second look are called out`() {
        assertNotNull(BleServices.notable("0000fe59-0000-1000-8000-00805f9b34fb"))
        assertTrue(
            BleServices.notable("00001812-0000-1000-8000-00805f9b34fb")!!.contains("Human Interface"),
        )
        assertNull(BleServices.notable("0000180f-0000-1000-8000-00805f9b34fb"))
    }

    @Test
    fun `a device's whole service list renders as names`() {
        val rendered = BleServices.describeAll(
            listOf("0000180f-0000-1000-8000-00805f9b34fb", "00001812-0000-1000-8000-00805f9b34fb"),
        )
        assertEquals("Battery, Human Interface Device", rendered)
    }
}
