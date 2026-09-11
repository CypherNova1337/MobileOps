package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.radio.BluetoothClassDecode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BluetoothClassDecodeTest {

    @Test
    fun `decodes a smartphone class of device`() {
        // 0x5A020C is the class an Android handset advertises: phone/smartphone offering
        // networking, capture, object transfer and telephony.
        val decoded = BluetoothClassDecode.decode(0x5A020C)
        assertEquals("phone", decoded.major)
        assertEquals("smartphone", decoded.minor)
        assertEquals(
            listOf("networking", "capture", "object transfer", "telephony"),
            decoded.services,
        )
        assertEquals("phone / smartphone", decoded.label)
    }

    @Test
    fun `decodes a hands-free car kit`() {
        // 0x240408: audio/video major, hands-free minor, audio service.
        val decoded = BluetoothClassDecode.decode(0x240408)
        assertEquals("audio/video", decoded.major)
        assertEquals("hands-free", decoded.minor)
        assertEquals(listOf("rendering", "audio"), decoded.services)
    }

    @Test
    fun `decodes a laptop`() {
        val decoded = BluetoothClassDecode.decode(0x10010C)
        assertEquals("computer", decoded.major)
        assertEquals("laptop", decoded.minor)
    }

    /** Peripherals pack the keyboard and pointer flags alongside the device type. */
    @Test
    fun `a keyboard and mouse combo reports both flags`() {
        val decoded = BluetoothClassDecode.decode(0x0005C0)
        assertEquals("peripheral", decoded.major)
        assertTrue(decoded.minor.contains("keyboard"))
        assertTrue(decoded.minor.contains("pointing device"))
    }

    @Test
    fun `a printer is recognised from the imaging minor field`() {
        val decoded = BluetoothClassDecode.decode(0x000680)
        assertEquals("imaging", decoded.major)
        assertEquals("printer", decoded.minor)
    }

    /** The data-carrying distinction is what decides whether a device is worth following up. */
    @Test
    fun `data services are told apart from audio-only ones`() {
        // A laptop advertising object transfer carries data; a hands-free kit does not.
        assertTrue(BluetoothClassDecode.carriesData(0x10010C))
        assertFalse(BluetoothClassDecode.carriesData(0x240408))
        // Networking on its own is enough.
        assertTrue(BluetoothClassDecode.carriesData(0x020000))
    }

    @Test
    fun `an unlisted major class is reported by number rather than guessed`() {
        val decoded = BluetoothClassDecode.decode(0x000A00)
        assertTrue(decoded.major.contains("0x0A"))
        assertEquals(decoded.major, decoded.label)
    }

    @Test
    fun `a zero class decodes without throwing`() {
        val decoded = BluetoothClassDecode.decode(0)
        assertEquals("miscellaneous", decoded.major)
        assertTrue(decoded.services.isEmpty())
    }
}
