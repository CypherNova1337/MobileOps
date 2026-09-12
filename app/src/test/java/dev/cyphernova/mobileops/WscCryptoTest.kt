package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.exploit.Wsc
import dev.cyphernova.mobileops.core.exploit.WscCrypto
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WscCryptoTest {

    @Test
    fun `diffie-hellman agreement is symmetric and fixed width`() {
        val registrar = WscCrypto.generateKeyPair()
        val enrollee = WscCrypto.generateKeyPair()

        assertEquals(WscCrypto.PUBLIC_KEY_BYTES, registrar.publicKey.size)
        assertEquals(WscCrypto.PUBLIC_KEY_BYTES, enrollee.publicKey.size)

        val fromRegistrar = registrar.agree(enrollee.publicKey)
        val fromEnrollee = enrollee.agree(registrar.publicKey)
        // Both sides must derive identical bytes, padded to the group size — a value that lost
        // its leading zero would hash differently and every later key would silently diverge.
        assertArrayEquals(fromRegistrar, fromEnrollee)
        assertEquals(WscCrypto.PUBLIC_KEY_BYTES, fromRegistrar.size)
    }

    @Test
    fun `session keys split into the three fields the spec defines`() {
        val keys = WscCrypto.deriveKeys(
            sharedSecret = ByteArray(192) { 7 },
            enrolleeNonce = ByteArray(16) { 1 },
            enrolleeMac = byteArrayOf(0, 1, 2, 3, 4, 5),
            registrarNonce = ByteArray(16) { 2 },
        )
        assertEquals(32, keys.authKey.size)
        assertEquals(16, keys.keyWrapKey.size)
        assertEquals(32, keys.emsk.size)
    }

    @Test
    fun `key derivation is deterministic and inputs actually matter`() {
        fun derive(macLastOctet: Byte) = WscCrypto.deriveKeys(
            sharedSecret = ByteArray(192) { 7 },
            enrolleeNonce = ByteArray(16) { 1 },
            enrolleeMac = byteArrayOf(0, 1, 2, 3, 4, macLastOctet),
            registrarNonce = ByteArray(16) { 2 },
        ).authKey

        assertArrayEquals(derive(5), derive(5))
        assertFalse(derive(5).contentEquals(derive(6)))
    }

    @Test
    fun `the kdf produces exactly the requested length`() {
        assertEquals(80, WscCrypto.kdf(ByteArray(32), "Wi-Fi Easy and Secure Key Derivation", 640).size)
        assertEquals(16, WscCrypto.kdf(ByteArray(32), "x", 128).size)
        // The requested length is bound into every block, so a shorter request is not a prefix.
        val long = WscCrypto.kdf(ByteArray(32), "x", 640)
        val short = WscCrypto.kdf(ByteArray(32), "x", 128)
        assertFalse(long.copyOfRange(0, 16).contentEquals(short))
    }

    @Test
    fun `pin halves produce different keys`() {
        val authKey = ByteArray(32) { it.toByte() }
        val (first, second) = WscCrypto.pinKeys(authKey, "12345670")
        assertEquals(16, first.size)
        assertEquals(16, second.size)
        assertFalse(first.contentEquals(second))

        // Only the matching half changes its own key: this is the split that makes the attack work.
        val (otherFirst, otherSecond) = WscCrypto.pinKeys(authKey, "12349999")
        assertArrayEquals(first, otherFirst)
        assertFalse(second.contentEquals(otherSecond))
    }

    @Test
    fun `encrypted settings round-trip and carry a key wrap authenticator`() {
        val keys = WscCrypto.SessionKeys(
            authKey = ByteArray(32) { 3 },
            keyWrapKey = ByteArray(16) { 4 },
            emsk = ByteArray(32),
        )
        val plaintext = Wsc.Builder().put(Wsc.Attr.R_SNONCE1, ByteArray(16) { 9 }).build()

        val wrapped = WscCrypto.encryptSettings(keys, plaintext)
        // IV plus at least one cipher block.
        assertTrue(wrapped.size >= 32)

        val unwrapped = WscCrypto.decryptSettings(keys, wrapped)
        assertNotNull(unwrapped)
        val attributes = Wsc.parse(unwrapped!!)
        assertArrayEquals(ByteArray(16) { 9 }, Wsc.first(attributes, Wsc.Attr.R_SNONCE1))
        assertEquals(8, Wsc.first(attributes, Wsc.Attr.KEY_WRAP_AUTHENTICATOR)!!.size)
    }

    @Test
    fun `a fresh iv is used for every wrap`() {
        val keys = WscCrypto.SessionKeys(ByteArray(32), ByteArray(16), ByteArray(32))
        val plaintext = Wsc.Builder().put(Wsc.Attr.R_SNONCE1, ByteArray(16)).build()
        assertFalse(
            WscCrypto.encryptSettings(keys, plaintext)
                .contentEquals(WscCrypto.encryptSettings(keys, plaintext)),
        )
    }

    /** A wrong PIN produces a wrong key-wrap key, and that must read as a miss, not a crash. */
    @Test
    fun `decrypting with the wrong key returns null rather than throwing`() {
        val right = WscCrypto.SessionKeys(ByteArray(32), ByteArray(16) { 1 }, ByteArray(32))
        val wrong = WscCrypto.SessionKeys(ByteArray(32), ByteArray(16) { 2 }, ByteArray(32))
        val wrapped = WscCrypto.encryptSettings(right, Wsc.Builder().put(0x1040, ByteArray(16)).build())
        assertNull(WscCrypto.decryptSettings(wrong, wrapped))
        assertNull(WscCrypto.decryptSettings(right, ByteArray(8)))
    }

    /**
     * Unpadding is not proof of the right key: AES-CBC/PKCS5 accepts garbage roughly once in
     * every 256 attempts, and a fresh IV per wrap means that lands eventually rather than never.
     * It cost a test failure on a clean tree to notice. A wrong PIN must always read as a miss,
     * so the plaintext has to parse as an attribute stream before it counts.
     */
    @Test
    fun `a wrong key never produces settings, however many times it is tried`() {
        val right = WscCrypto.SessionKeys(ByteArray(32), ByteArray(16) { 1 }, ByteArray(32))
        val wrong = WscCrypto.SessionKeys(ByteArray(32), ByteArray(16) { 2 }, ByteArray(32))
        val plaintext = Wsc.Builder().put(0x1040, ByteArray(16)).build()
        repeat(2000) {
            assertNull(WscCrypto.decryptSettings(wrong, WscCrypto.encryptSettings(right, plaintext)))
        }
    }

    @Test
    fun `the authenticator is the first sixty-four bits of the hmac`() {
        val authKey = ByteArray(32) { 5 }
        val authenticator = WscCrypto.authenticator(authKey, byteArrayOf(1), byteArrayOf(2))
        assertEquals(8, authenticator.size)
        assertArrayEquals(
            WscCrypto.hmac(authKey, byteArrayOf(1, 2)).copyOfRange(0, 8),
            authenticator,
        )
    }

    @Test
    fun `commitment binds the nonce, the pin key and both public keys`() {
        val authKey = ByteArray(32) { 6 }
        val base = WscCrypto.commitment(authKey, ByteArray(16), ByteArray(16), ByteArray(192), ByteArray(192))
        val changed = WscCrypto.commitment(
            authKey,
            ByteArray(16),
            ByteArray(16) { 1 },
            ByteArray(192),
            ByteArray(192),
        )
        assertEquals(32, base.size)
        assertFalse(base.contentEquals(changed))
    }
}
