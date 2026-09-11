package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.beacon.BeaconElements
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

class BeaconElementsTest {

    private val ieee = byteArrayOf(0x00, 0x0F, 0xAC.toByte())

    /** Builds an RSN element payload the way an AP actually emits one. */
    private fun rsn(
        groupCipher: Int = 4,
        pairwise: List<Int> = listOf(4),
        akms: List<Int> = listOf(2),
        capabilities: Int? = 0x0000,
    ): ByteArray = ByteArrayOutputStream().apply {
        write(byteArrayOf(0x01, 0x00))                    // version 1, little-endian
        write(ieee); write(groupCipher)
        write(byteArrayOf((pairwise.size and 0xFF).toByte(), 0x00))
        pairwise.forEach { write(ieee); write(it) }
        write(byteArrayOf((akms.size and 0xFF).toByte(), 0x00))
        akms.forEach { write(ieee); write(it) }
        capabilities?.let { write(byteArrayOf((it and 0xFF).toByte(), ((it shr 8) and 0xFF).toByte())) }
    }.toByteArray()

    /** Builds a WPS vendor element payload, big-endian TLVs after the OUI and type. */
    private fun wps(vararg attributes: Pair<Int, ByteArray>): ByteArray = ByteArrayOutputStream().apply {
        write(byteArrayOf(0x00, 0x50, 0xF2.toByte(), 0x04))
        attributes.forEach { (type, value) ->
            write(byteArrayOf(((type shr 8) and 0xFF).toByte(), (type and 0xFF).toByte()))
            write(byteArrayOf(((value.size shr 8) and 0xFF).toByte(), (value.size and 0xFF).toByte()))
            write(value)
        }
    }.toByteArray()

    @Test
    fun `reads a wpa2 psk rsn element`() {
        val info = BeaconElements.parseRsn(rsn())!!
        assertEquals("CCMP-128", info.groupCipher)
        assertEquals(listOf("CCMP-128"), info.pairwiseCiphers)
        assertEquals(listOf("PSK"), info.akmSuites)
        assertTrue(info.usesPsk)
        assertFalse(info.usesSae)
        assertFalse(info.hasWeakCipher)
    }

    @Test
    fun `identifies wpa3 transition mode from the akm list`() {
        val info = BeaconElements.parseRsn(rsn(akms = listOf(2, 8)))!!
        assertTrue(info.usesSae)
        assertTrue(info.usesPsk)
        assertTrue(info.isWpa3Transition)
    }

    @Test
    fun `flags tkip as a weak cipher`() {
        assertTrue(BeaconElements.parseRsn(rsn(pairwise = listOf(4, 2)))!!.hasWeakCipher)
        assertTrue(BeaconElements.parseRsn(rsn(groupCipher = 2))!!.hasWeakCipher)
    }

    @Test
    fun `separates management frame protection required from capable`() {
        // The distinction the capability string cannot express: an AP that supports 802.11w but
        // does not insist on it leaves any client that declines fully exposed.
        val required = BeaconElements.parseRsn(rsn(capabilities = 0x00C0))!!
        assertTrue(required.managementFrameProtectionRequired)
        assertTrue(required.managementFrameProtectionCapable)

        val optional = BeaconElements.parseRsn(rsn(capabilities = 0x0080))!!
        assertFalse(optional.managementFrameProtectionRequired)
        assertTrue(optional.managementFrameProtectionCapable)

        val absent = BeaconElements.parseRsn(rsn(capabilities = 0x0000))!!
        assertFalse(absent.managementFrameProtectionCapable)
    }

    @Test
    fun `an rsn element with no capability field is still parsed`() {
        val info = BeaconElements.parseRsn(rsn(capabilities = null))!!
        assertEquals(listOf("PSK"), info.akmSuites)
        assertFalse(info.managementFrameProtectionCapable)
    }

    @Test
    fun `recognises enterprise and owe akms`() {
        assertTrue(BeaconElements.parseRsn(rsn(akms = listOf(1)))!!.usesEnterprise)
        assertTrue(BeaconElements.parseRsn(rsn(akms = listOf(18)))!!.usesOwe)
    }

    @Test
    fun `a vendor suite is reported rather than mistaken for a standard one`() {
        val payload = ByteArrayOutputStream().apply {
            write(byteArrayOf(0x01, 0x00))
            write(byteArrayOf(0x00, 0x11, 0x22)); write(4)   // vendor OUI
            write(byteArrayOf(0x01, 0x00)); write(ieee); write(4)
            write(byteArrayOf(0x01, 0x00)); write(ieee); write(2)
            write(byteArrayOf(0x00, 0x00))
        }.toByteArray()
        assertTrue(BeaconElements.parseRsn(payload)!!.groupCipher.startsWith("vendor-"))
    }

    @Test
    fun `malformed rsn returns null rather than throwing`() {
        assertNull(BeaconElements.parseRsn(ByteArray(0)))
        assertNull(BeaconElements.parseRsn(byteArrayOf(0x01, 0x00)))
        val truncated = rsn()
        for (cut in 0 until truncated.size) {
            BeaconElements.parseRsn(truncated.copyOf(cut))
        }
    }

    @Test
    fun `reads the wps lock state that decides exploitability`() {
        val locked = BeaconElements.parse(
            listOf(221 to wps(0x1057 to byteArrayOf(0x01))),
        ).wps!!
        assertEquals(true, locked.setupLocked)

        val unlocked = BeaconElements.parse(
            listOf(221 to wps(0x1057 to byteArrayOf(0x00))),
        ).wps!!
        assertEquals(false, unlocked.setupLocked)
    }

    @Test
    fun `absent lock attribute is unknown rather than assumed unlocked`() {
        // Reporting "unlocked" for an AP that simply did not say would invent an attack path.
        val info = BeaconElements.parse(listOf(221 to wps(0x1044 to byteArrayOf(0x02)))).wps!!
        assertNull(info.setupLocked)
        assertEquals(true, info.configured)
    }

    @Test
    fun `reads device identity and version from wps`() {
        val info = BeaconElements.parse(
            listOf(
                221 to wps(
                    0x104A to byteArrayOf(0x10),
                    0x1021 to "Netgear".toByteArray(),
                    0x1023 to "R7000".toByteArray(),
                    0x1024 to "V1".toByteArray(),
                    0x1011 to "MyRouter".toByteArray(),
                    0x1012 to byteArrayOf(0x00, 0x04),
                ),
            ),
        ).wps!!

        assertEquals("1.0", info.version)
        assertEquals("Netgear", info.manufacturer)
        assertEquals("R7000", info.modelName)
        assertEquals("V1", info.modelNumber)
        assertEquals("MyRouter", info.deviceName)
        assertTrue(info.pushButtonActive)
    }

    @Test
    fun `detects legacy wpa alongside rsn`() {
        val legacyWpa = byteArrayOf(0x00, 0x50, 0xF2.toByte(), 0x01, 0x01, 0x00)
        val profile = BeaconElements.parse(listOf(48 to rsn(), 221 to legacyWpa))
        assertTrue(profile.legacyWpaPresent)
        assertTrue(profile.vendorOuis.contains("00:50:F2"))
    }

    @Test
    fun `reports radio generation from element ids`() {
        val profile = BeaconElements.parse(listOf(45 to ByteArray(2), 191 to ByteArray(2)))
        assertTrue(profile.supportsHt)
        assertTrue(profile.supportsVht)
        assertFalse(profile.supportsHe)
    }

    @Test
    fun `a truncated wps element yields what was readable`() {
        val full = wps(0x1021 to "Netgear".toByteArray(), 0x1057 to byteArrayOf(0x00))
        for (cut in 4 until full.size) {
            BeaconElements.parse(listOf(221 to full.copyOf(cut)))
        }
        assertNull(BeaconElements.parseWps(ByteArray(0)))
    }

    @Test
    fun `an empty element list produces an empty profile`() {
        val profile = BeaconElements.parse(emptyList())
        assertNull(profile.wps)
        assertNull(profile.rsn)
        assertFalse(profile.legacyWpaPresent)
    }
}
