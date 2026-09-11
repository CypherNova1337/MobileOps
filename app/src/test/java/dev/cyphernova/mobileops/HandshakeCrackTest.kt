package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.crack.CandidateSource
import dev.cyphernova.mobileops.core.crack.CaptureFormats
import dev.cyphernova.mobileops.core.crack.HandshakeCapture
import dev.cyphernova.mobileops.core.crack.PassphraseSearch
import dev.cyphernova.mobileops.core.crack.WpaCrypto
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class HandshakeCrackTest {

    private fun bytes(value: String) = ByteArray(value.length / 2) {
        value.substring(it * 2, it * 2 + 2).toInt(16).toByte()
    }

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

    private val apMac = bytes("80cc9c1318c4")
    private val staMac = bytes("aabbccddeeff")

    /**
     * Builds a PMKID the way an AP would, so the search is tested against a target that is
     * genuinely solvable rather than against its own output.
     */
    private fun pmkidCapture(ssid: String, passphrase: String): HandshakeCapture.Pmkid {
        val pmk = WpaCrypto.pmk(passphrase, ssid)!!
        return HandshakeCapture.Pmkid(ssid, apMac, staMac, WpaCrypto.pmkid(pmk, apMac, staMac))
    }

    /**
     * Builds a four-way handshake the way a supplicant would: derive the PTK, sign the frame
     * with the KCK, and put the result in the MIC field. That exercises the PRF, the PTK
     * derivation, the MIC and the frame parsing together.
     */
    private fun eapolCapture(ssid: String, passphrase: String): HandshakeCapture.Eapol {
        val aNonce = ByteArray(32) { (it * 3).toByte() }
        val sNonce = ByteArray(32) { (it * 7).toByte() }

        val frame = ByteArray(121)
        frame[0] = 2 // 802.1X version
        frame[1] = 3 // EAPOL-Key
        frame[2] = 0
        frame[3] = 117
        frame[4] = 2 // RSN key descriptor
        frame[5] = 0x01
        frame[6] = 0x0A // key information, low three bits = descriptor version 2
        sNonce.copyInto(frame, 17)

        val pmk = WpaCrypto.pmk(passphrase, ssid)!!
        val ptk = WpaCrypto.ptk(pmk, apMac, staMac, aNonce, sNonce)
        val mic = WpaCrypto.mic(WpaCrypto.kck(ptk), frame, 2)!!

        val signed = frame.copyOf()
        mic.copyInto(signed, 81)
        return CaptureFormats.eapolHandshake(ssid, apMac, staMac, aNonce, mic, signed)!!
    }

    @Test
    fun `a pmkid is verified by the right passphrase and only that one`() {
        val capture = pmkidCapture("VoidSec", "correcthorse")
        assertTrue(PassphraseSearch.matches(capture, "correcthorse"))
        assertFalse(PassphraseSearch.matches(capture, "correcthorse1"))
        assertFalse(PassphraseSearch.matches(capture, "password"))
    }

    @Test
    fun `a four-way handshake is verified end to end`() {
        val capture = eapolCapture("VoidSec", "hunter2hunter2")
        assertEquals(2, capture.keyDescriptorVersion)
        // The SNonce must have been read out of the frame rather than invented.
        assertEquals(hex(ByteArray(32) { (it * 7).toByte() }), hex(capture.sNonce))
        assertTrue(PassphraseSearch.matches(capture, "hunter2hunter2"))
        assertFalse(PassphraseSearch.matches(capture, "hunter2hunter3"))
    }

    /** The MIC cannot sign itself, so the field must be zeroed before the frame is hashed. */
    @Test
    fun `the mic field is zeroed in the frame that gets signed`() {
        val capture = eapolCapture("VoidSec", "hunter2hunter2")
        assertTrue(capture.eapolFrame.copyOfRange(81, 97).all { it == 0.toByte() })
        assertFalse(capture.mic.all { it == 0.toByte() })
    }

    @Test
    fun `the search walks candidates and reports which one landed`() = runTest {
        val capture = pmkidCapture("VoidSec", "letmein1")
        val result = PassphraseSearch.search(
            ssid = "VoidSec",
            captures = listOf(capture),
            candidates = sequenceOf("password", "12345678", "letmein1", "neverreached"),
            total = 4,
        )
        assertTrue(result is PassphraseSearch.Result.Found)
        result as PassphraseSearch.Result.Found
        assertEquals("letmein1", result.passphrase)
        assertEquals(3, result.tried)
    }

    @Test
    fun `a search that finds nothing says so rather than claiming the network is secure`() = runTest {
        val capture = pmkidCapture("VoidSec", "notinthelist")
        val result = PassphraseSearch.search(
            ssid = "VoidSec",
            captures = listOf(capture),
            candidates = sequenceOf("password", "12345678"),
            total = 2,
        )
        assertTrue(result is PassphraseSearch.Result.Exhausted)
        assertEquals(2, (result as PassphraseSearch.Result.Exhausted).tried)
    }

    @Test
    fun `a capture for another network is not attacked`() = runTest {
        val result = PassphraseSearch.search(
            ssid = "VoidSec",
            captures = listOf(pmkidCapture("SomeoneElse", "password")),
            candidates = sequenceOf("password"),
            total = 1,
        )
        assertTrue(result is PassphraseSearch.Result.Stopped)
    }

    @Test
    fun `a deadline stops the search rather than running forever`() = runTest {
        val result = PassphraseSearch.search(
            ssid = "VoidSec",
            captures = listOf(pmkidCapture("VoidSec", "unreachable1")),
            candidates = generateSequence { "candidate1" },
            total = 0,
            shouldContinue = { false },
        )
        assertTrue(result is PassphraseSearch.Result.Stopped)
    }

    @Test
    fun `22000 pmkid records round-trip`() {
        val capture = pmkidCapture("VoidSec", "correcthorse")
        val essidHex = hex("VoidSec".toByteArray())
        val line = "WPA*01*${hex(capture.pmkid)}*${hex(apMac)}*${hex(staMac)}*$essidHex***"

        val parsed = CaptureFormats.parse22000(line)
        assertEquals(1, parsed.size)
        val only = parsed.single() as HandshakeCapture.Pmkid
        assertEquals("VoidSec", only.ssid)
        assertEquals(hex(capture.pmkid), hex(only.pmkid))
        assertTrue(PassphraseSearch.matches(only, "correcthorse"))
    }

    @Test
    fun `22000 handshake records round-trip`() {
        val capture = eapolCapture("VoidSec", "hunter2hunter2")
        val signed = capture.eapolFrame.copyOf().also { capture.mic.copyInto(it, 81) }
        val line = listOf(
            "WPA", "02", hex(capture.mic), hex(apMac), hex(staMac),
            hex("VoidSec".toByteArray()), hex(capture.aNonce), hex(signed), "02",
        ).joinToString("*")

        val parsed = CaptureFormats.parse22000(line).single() as HandshakeCapture.Eapol
        assertEquals("VoidSec", parsed.ssid)
        assertEquals(2, parsed.keyDescriptorVersion)
        assertTrue(PassphraseSearch.matches(parsed, "hunter2hunter2"))
    }

    /** These files are routinely hand-edited and half-written by interrupted tools. */
    @Test
    fun `malformed lines are skipped rather than throwing`() {
        val text = """
            not a record at all
            WPA*01*tooshort*zz*yy*nothex***
            WPA*99*ffffffffffffffffffffffffffffffff*80cc9c1318c4*aabbccddeeff*566f6964536563***
            WPA*01*ffffffffffffffffffffffffffffffff*80cc9c1318c4*aabbccddeeff*566f6964536563***
        """.trimIndent()
        val parsed = CaptureFormats.parse22000(text)
        assertEquals(1, parsed.size)
        assertEquals("VoidSec", parsed.single().ssid)
    }

    @Test
    fun `hex decoding refuses anything that is not a whole number of bytes`() {
        assertNull(CaptureFormats.hex("abc"))
        assertNull(CaptureFormats.hex("zz"))
        assertNull(CaptureFormats.hex(""))
        assertNotNull(CaptureFormats.hex("00ff"))
    }

    @Test
    fun `hccapx records are read from their fixed offsets`() {
        val capture = eapolCapture("VoidSec", "hunter2hunter2")
        val signed = capture.eapolFrame.copyOf().also { capture.mic.copyInto(it, 81) }

        val record = ByteArray(393)
        "HCPX".toByteArray().copyInto(record)
        record[4] = 4
        record[8] = 2
        record[9] = "VoidSec".length.toByte()
        "VoidSec".toByteArray().copyInto(record, 10)
        record[42] = 2
        capture.mic.copyInto(record, 43)
        apMac.copyInto(record, 59)
        capture.aNonce.copyInto(record, 65)
        staMac.copyInto(record, 97)
        capture.sNonce.copyInto(record, 103)
        record[135] = (signed.size and 0xFF).toByte()
        record[136] = ((signed.size shr 8) and 0xFF).toByte()
        signed.copyInto(record, 137)

        val parsed = CaptureFormats.parseHccapx(record).single() as HandshakeCapture.Eapol
        assertEquals("VoidSec", parsed.ssid)
        assertTrue(PassphraseSearch.matches(parsed, "hunter2hunter2"))
    }

    @Test
    fun `a record without the hccapx signature is ignored`() {
        assertTrue(CaptureFormats.parseHccapx(ByteArray(393)).isEmpty())
        assertTrue(CaptureFormats.parseHccapx(ByteArray(10)).isEmpty())
    }

    @Test
    fun `ssid-derived candidates stay inside the legal passphrase length`() {
        val candidates = CandidateSource.fromSsid("VoidSec")
        assertTrue(candidates.isNotEmpty())
        assertTrue(candidates.all { it.length in CandidateSource.MIN_LENGTH..CandidateSource.MAX_LENGTH })
        assertTrue(candidates.contains("VoidSec1"))
        assertTrue(candidates.contains("voidsec123"))
        assertEquals(candidates.distinct().size, candidates.size)
    }

    @Test
    fun `a blank ssid yields no candidates and the built-in list is all legal`() {
        assertTrue(CandidateSource.fromSsid("   ").isEmpty())
        assertTrue(
            CandidateSource.COMMON.all {
                it.length in CandidateSource.MIN_LENGTH..CandidateSource.MAX_LENGTH
            },
        )
    }
}
