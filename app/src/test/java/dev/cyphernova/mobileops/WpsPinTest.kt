package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.exploit.WpsPin
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WpsPinTest {

    /** The checksum digit is what an AP validates before doing any crypto at all. */
    @Test
    fun `checksum matches the canonical example pin`() {
        assertEquals(0, WpsPin.checksum(1234567))
        assertEquals("12345670", WpsPin.withChecksum(1234567))
    }

    @Test
    fun `checksum digit is recomputable from the pin itself`() {
        // Any PIN this produces must survive the AP's own check, which is the same arithmetic.
        listOf(0, 1, 999, 4626484, 9999999).forEach { body ->
            val pin = WpsPin.withChecksum(body)
            assertEquals(8, pin.length)
            val recomputed = WpsPin.checksum(pin.substring(0, 7).toInt())
            assertEquals(pin.substring(7).toInt(), recomputed)
        }
    }

    @Test
    fun `every derived candidate carries a valid checksum`() {
        val candidates = WpsPin.candidatesFor("80:CC:9C:13:18:C4")
        assertTrue(candidates.size > 5)
        candidates.forEach { candidate ->
            assertEquals(8, candidate.pin.length)
            assertTrue(candidate.pin.all(Char::isDigit))
            assertEquals(
                candidate.pin.substring(7).toInt(),
                WpsPin.checksum(candidate.pin.substring(0, 7).toInt()),
            )
        }
    }

    @Test
    fun `the 24-bit derivation uses the last three octets`() {
        // 0x1318C4 = 1251012, which is under ten million and so is used unchanged.
        val expected = WpsPin.withChecksum(0x1318C4)
        val candidates = WpsPin.candidatesFor("80:CC:9C:13:18:C4")
        assertEquals(expected, candidates.first { it.algorithm == "24-bit NIC" }.pin)
    }

    @Test
    fun `candidates are deduplicated`() {
        val candidates = WpsPin.candidatesFor("00:00:00:00:00:00")
        assertEquals(candidates.map { it.pin }.distinct().size, candidates.size)
    }

    @Test
    fun `derivation is stable across separator and case`() {
        assertEquals(
            WpsPin.candidatesFor("80:CC:9C:13:18:C4").map { it.pin },
            WpsPin.candidatesFor("80-cc-9c-13-18-c4").map { it.pin },
        )
    }

    @Test
    fun `a bssid that is not a mac still yields the static defaults`() {
        assertNull(WpsPin.macBytes("not-a-mac"))
        val candidates = WpsPin.candidatesFor("not-a-mac")
        assertTrue(candidates.isNotEmpty())
        assertTrue(candidates.all { it.algorithm == "known default" })
    }

    @Test
    fun `mac parsing accepts the separators that turn up in the wild`() {
        val expected = byteArrayOf(0x80.toByte(), 0xCC.toByte(), 0x9C.toByte(), 0x13, 0x18, 0xC4.toByte())
        listOf("80:CC:9C:13:18:C4", "80-CC-9C-13-18-C4", "80CC9C1318C4").forEach { input ->
            val parsed = WpsPin.macBytes(input)
            assertNotNull(parsed)
            assertTrue(expected.contentEquals(parsed))
        }
    }
}
