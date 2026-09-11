package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.exploit.Wsc
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WscTest {

    @Test
    fun `attributes round-trip through the codec`() {
        val encoded = Wsc.Builder()
            .putByte(Wsc.Attr.VERSION, 0x10)
            .putByte(Wsc.Attr.MESSAGE_TYPE, Wsc.Message.M2)
            .put(Wsc.Attr.ENROLLEE_NONCE, ByteArray(16) { it.toByte() })
            .putText(Wsc.Attr.DEVICE_NAME, "Registrar")
            .build()

        val parsed = Wsc.parse(encoded)
        assertEquals(4, parsed.size)
        assertEquals(Wsc.Message.M2, Wsc.messageType(encoded))
        assertEquals("Registrar", Wsc.first(parsed, Wsc.Attr.DEVICE_NAME)!!.toString(Charsets.UTF_8))
        assertEquals(16, Wsc.first(parsed, Wsc.Attr.ENROLLEE_NONCE)!!.size)
    }

    @Test
    fun `multi-byte values are written big-endian`() {
        val encoded = Wsc.Builder().putShort(Wsc.Attr.CONFIG_METHODS, 0x018C).build()
        // Type high, type low, length high, length low, then the value.
        assertTrue(
            byteArrayOf(0x10, 0x08, 0x00, 0x02, 0x01, 0x8C.toByte()).contentEquals(encoded),
        )
        assertEquals(4, Wsc.Builder().putInt(Wsc.Attr.OS_VERSION, 1).build().size - 4)
    }

    /** These bytes come off the network from a device that may be lying about them. */
    @Test
    fun `a length running past the buffer stops parsing rather than throwing`() {
        val truncated = byteArrayOf(0x10, 0x1A, 0x00, 0x40, 0x01, 0x02)
        assertTrue(Wsc.parse(truncated).isEmpty())
    }

    @Test
    fun `trailing bytes too short for a header are ignored`() {
        val encoded = Wsc.Builder().putByte(Wsc.Attr.VERSION, 0x10).build() + byteArrayOf(0x10, 0x22)
        assertEquals(1, Wsc.parse(encoded).size)
    }

    @Test
    fun `a message with no type reports none`() {
        assertNull(Wsc.messageType(Wsc.Builder().putByte(Wsc.Attr.VERSION, 0x10).build()))
        assertNull(Wsc.messageType(ByteArray(0)))
    }

    @Test
    fun `message helper emits version then type`() {
        val parsed = Wsc.parse(Wsc.message(Wsc.Message.M4).build())
        assertEquals(Wsc.Attr.VERSION, parsed[0].first)
        assertEquals(Wsc.Attr.MESSAGE_TYPE, parsed[1].first)
        assertEquals("M4", Wsc.Message.name(Wsc.Message.M4))
    }

    @Test
    fun `a repeated attribute is kept rather than collapsed`() {
        val encoded = Wsc.Builder()
            .putText(Wsc.Attr.CREDENTIAL, "one")
            .putText(Wsc.Attr.CREDENTIAL, "two")
            .build()
        assertEquals(2, Wsc.parse(encoded).size)
        assertEquals("one", Wsc.first(Wsc.parse(encoded), Wsc.Attr.CREDENTIAL)!!.toString(Charsets.UTF_8))
    }
}
