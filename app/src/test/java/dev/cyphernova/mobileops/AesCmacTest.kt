package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.crack.AesCmac
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class AesCmacTest {

    private val key = bytes("2b7e151628aed2a6abf7158809cf4f3c")

    private fun bytes(value: String) = ByteArray(value.length / 2) {
        value.substring(it * 2, it * 2 + 2).toInt(16).toByte()
    }

    private fun cmac(message: String) =
        AesCmac.compute(key, bytes(message))!!.joinToString("") { "%02x".format(it) }

    /**
     * The four RFC 4493 vectors, which between them cover every branch: the empty message, one
     * complete block, a partial final block needing padding, and several complete blocks. Pinned
     * because a subtly wrong CMAC shows up only as WPA3-era handshakes never verifying.
     */
    @Test
    fun `matches the rfc 4493 vectors`() {
        assertEquals("bb1d6929e95937287fa37d129b756746", cmac(""))
        assertEquals(
            "070a16b46b4d4144f79bdd9dd04a287c",
            cmac("6bc1bee22e409f96e93d7e117393172a"),
        )
        assertEquals(
            "dfa66747de9ae63030ca32611497c827",
            cmac(
                "6bc1bee22e409f96e93d7e117393172a" +
                    "ae2d8a571e03ac9c9eb76fac45af8e51" +
                    "30c81c46a35ce411",
            ),
        )
        assertEquals(
            "51f0bebf7e3b9d92fc49741779363cfe",
            cmac(
                "6bc1bee22e409f96e93d7e117393172a" +
                    "ae2d8a571e03ac9c9eb76fac45af8e51" +
                    "30c81c46a35ce411e5fbc1191a0a52ef" +
                    "f69f2445df4f9b17ad2b417be66c3710",
            ),
        )
    }

    @Test
    fun `output is always one block`() {
        listOf(0, 1, 15, 16, 17, 99, 128).forEach { size ->
            assertEquals(16, AesCmac.compute(key, ByteArray(size))!!.size)
        }
    }

    /** The padding branch must make a short message distinct from the same bytes zero-extended. */
    @Test
    fun `a padded message differs from a zero-extended one`() {
        val short = AesCmac.compute(key, ByteArray(15) { 1 })!!
        val extended = AesCmac.compute(key, ByteArray(16) { if (it < 15) 1 else 0 })!!
        assertEquals(false, short.contentEquals(extended))
    }

    @Test
    fun `a key the cipher cannot take returns null rather than throwing`() {
        assertNull(AesCmac.compute(ByteArray(7), ByteArray(16)))
        assertNotNull(AesCmac.compute(ByteArray(16), ByteArray(16)))
    }
}
