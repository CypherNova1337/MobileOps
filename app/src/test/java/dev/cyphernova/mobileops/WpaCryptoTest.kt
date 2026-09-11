package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.crack.AesCmac
import dev.cyphernova.mobileops.core.crack.WpaCrypto
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WpaCryptoTest {

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

    private fun bytes(value: String) = ByteArray(value.length / 2) {
        value.substring(it * 2, it * 2 + 2).toInt(16).toByte()
    }

    /**
     * The published 802.11i passphrase-to-PSK vectors. Everything else in the attack rests on
     * this being right, and a wrong PMK fails silently as "passphrase not found" rather than as
     * an error — so it is pinned against known values rather than checked for self-consistency.
     */
    @Test
    fun `pmk matches the published test vectors`() {
        assertEquals(
            "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e",
            hex(WpaCrypto.pmk("password", "IEEE")!!),
        )
        assertEquals(
            "0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af",
            hex(WpaCrypto.pmk("ThisIsAPassword", "ThisIsASSID")!!),
        )
        assertEquals(
            "2d43d0dabfdd635377172efa1fc4b4b87dbfc4219193909ded9a7cfb89a3097b",
            hex(WpaCrypto.pmk("a".repeat(63), "Z".repeat(32))!!),
        )
    }

    /** Outside 8..63 characters an AP would not have accepted it, so testing it is wasted work. */
    @Test
    fun `passphrases outside the legal length are rejected rather than derived`() {
        assertNull(WpaCrypto.pmk("short", "Net"))
        assertNull(WpaCrypto.pmk("a".repeat(64), "Net"))
        assertNotNull(WpaCrypto.pmk("a".repeat(8), "Net"))
    }

    @Test
    fun `the ssid is the salt, so the same passphrase gives different keys per network`() {
        assertFalse(
            WpaCrypto.pmk("password", "NetworkA")!!
                .contentEquals(WpaCrypto.pmk("password", "NetworkB")!!),
        )
    }

    @Test
    fun `the prf produces the requested length and is deterministic`() {
        val key = ByteArray(32) { 1 }
        val data = ByteArray(76) { 2 }
        assertEquals(48, WpaCrypto.prf(key, "Pairwise key expansion", data, 384).size)
        assertArrayEquals(
            WpaCrypto.prf(key, "Pairwise key expansion", data, 384),
            WpaCrypto.prf(key, "Pairwise key expansion", data, 384),
        )
        // The counter is appended per block, so a longer request extends rather than replaces.
        val short = WpaCrypto.prf(key, "L", data, 160)
        val long = WpaCrypto.prf(key, "L", data, 384)
        assertArrayEquals(short, long.copyOfRange(0, 20))
    }

    /**
     * Both sides sort the addresses and nonces before hashing, which is what lets them derive
     * the same key without agreeing who goes first — and which means a capture is usable
     * whichever way round the two MACs were recorded.
     */
    @Test
    fun `ptk derivation is independent of which side is named first`() {
        val pmk = WpaCrypto.pmk("password", "IEEE")!!
        val ap = bytes("001122334455")
        val sta = bytes("aabbccddeeff")
        val aNonce = ByteArray(32) { 3 }
        val sNonce = ByteArray(32) { 4 }

        assertArrayEquals(
            WpaCrypto.ptk(pmk, ap, sta, aNonce, sNonce),
            WpaCrypto.ptk(pmk, sta, ap, sNonce, aNonce),
        )
    }

    /** A MAC octet above 0x7F must not sort as negative, or the key comes out wrong. */
    @Test
    fun `address ordering treats octets as unsigned`() {
        val pmk = ByteArray(32) { 5 }
        val low = bytes("001122334455")
        val high = bytes("ff1122334455")
        val nonce = ByteArray(32)
        // Whichever order they arrive in, the derived key is the same one.
        assertArrayEquals(
            WpaCrypto.ptk(pmk, low, high, nonce, nonce),
            WpaCrypto.ptk(pmk, high, low, nonce, nonce),
        )
    }

    @Test
    fun `ptk splits into the fields the layout defines`() {
        val ptk = WpaCrypto.ptk(ByteArray(32), ByteArray(6), ByteArray(6), ByteArray(32), ByteArray(32))
        assertEquals(48, ptk.size)
        assertEquals(16, WpaCrypto.kck(ptk).size)
        assertArrayEquals(ptk.copyOfRange(0, 16), WpaCrypto.kck(ptk))
    }

    @Test
    fun `pmkid is derived from the pmk and both addresses`() {
        val pmk = WpaCrypto.pmk("password", "IEEE")!!
        val ap = bytes("001122334455")
        val sta = bytes("aabbccddeeff")

        val pmkid = WpaCrypto.pmkid(pmk, ap, sta)
        assertEquals(16, pmkid.size)
        // Unlike the PTK, this one is not order-independent: it names the AP first by definition.
        assertFalse(pmkid.contentEquals(WpaCrypto.pmkid(pmk, sta, ap)))
        assertArrayEquals(pmkid, WpaCrypto.pmkid(pmk, ap, sta))
    }

    /**
     * Choosing the wrong MIC algorithm is the usual reason a correct passphrase appears to fail,
     * so the three key descriptor versions must stay distinct and an unknown one must not be
     * silently treated as a default.
     */
    @Test
    fun `each key descriptor version signs with its own algorithm`() {
        val kck = ByteArray(16) { 7 }
        val frame = ByteArray(99) { it.toByte() }

        val md5 = WpaCrypto.mic(kck, frame, 1)!!
        val sha1 = WpaCrypto.mic(kck, frame, 2)!!
        val cmac = WpaCrypto.mic(kck, frame, 3)!!

        listOf(md5, sha1, cmac).forEach { assertEquals(16, it.size) }
        assertFalse(md5.contentEquals(sha1))
        assertFalse(sha1.contentEquals(cmac))
        assertArrayEquals(WpaCrypto.hmacMd5(kck, frame), md5)
        assertArrayEquals(WpaCrypto.hmacSha1(kck, frame).copyOfRange(0, 16), sha1)
        assertArrayEquals(AesCmac.compute(kck, frame), cmac)

        assertNull(WpaCrypto.mic(kck, frame, 0))
        assertNull(WpaCrypto.mic(kck, frame, 4))
    }
}
