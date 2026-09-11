package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.iot.IotProbes
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IotProbesTest {

    private fun hex(bytes: ByteArray) = bytes.joinToString(" ") { "%02x".format(it) }

    // ------------------------------------------------------------------ MQTT

    @Test
    fun `mqtt connect is a well-formed 3 1 1 packet with no credentials`() {
        val packet = IotProbes.mqttConnect("probe")
        assertEquals(0x10, packet[0].toInt() and 0xFF)
        // Remaining length, then the protocol name as a length-prefixed string.
        assertEquals(packet.size - 2, packet[1].toInt() and 0xFF)
        assertEquals("MQTT", String(packet, 4, 4, Charsets.US_ASCII))
        assertEquals(0x04, packet[8].toInt() and 0xFF) // protocol level 4
        // Connect flags: clean session only. The credential bits must be clear.
        assertEquals(0x02, packet[9].toInt() and 0xFF)
        assertEquals("probe", String(packet, packet.size - 5, 5, Charsets.US_ASCII))
    }

    /** The variable-length integer is the part of MQTT framing that is easy to get wrong. */
    @Test
    fun `mqtt remaining length encodes across its continuation boundaries`() {
        assertArrayEquals(byteArrayOf(0x00), IotProbes.remainingLength(0))
        assertArrayEquals(byteArrayOf(0x7F), IotProbes.remainingLength(127))
        assertArrayEquals(byteArrayOf(0x80.toByte(), 0x01), IotProbes.remainingLength(128))
        assertArrayEquals(byteArrayOf(0xFF.toByte(), 0x7F), IotProbes.remainingLength(16383))
        assertArrayEquals(
            byteArrayOf(0x80.toByte(), 0x80.toByte(), 0x01),
            IotProbes.remainingLength(16384),
        )
    }

    @Test
    fun `a connack return code of zero is anonymous access`() {
        val accepted = IotProbes.parseMqttConnack(byteArrayOf(0x20, 0x02, 0x00, 0x00))!!
        assertTrue(accepted.accepted)
        assertTrue(accepted.meaning.contains("without credentials"))

        val refused = IotProbes.parseMqttConnack(byteArrayOf(0x20, 0x02, 0x00, 0x05))!!
        assertFalse(refused.accepted)
        assertTrue(refused.meaning.contains("not authorised"))
    }

    @Test
    fun `a packet that is not a connack is not read as one`() {
        assertNull(IotProbes.parseMqttConnack(byteArrayOf(0x30, 0x02, 0x00, 0x00)))
        assertNull(IotProbes.parseMqttConnack(byteArrayOf(0x20)))
    }

    // ------------------------------------------------------------------ CoAP

    @Test
    fun `coap request asks for the well-known core directory`() {
        val packet = IotProbes.coapWellKnownCore(0x1234)
        assertEquals(0x40, packet[0].toInt() and 0xFF) // version 1, confirmable, no token
        assertEquals(0x01, packet[1].toInt() and 0xFF) // GET
        assertEquals(0x12, packet[2].toInt() and 0xFF)
        assertEquals(0x34, packet[3].toInt() and 0xFF)
        // Uri-Path option 11, eleven bytes: delta 11 in the high nibble, length in the low.
        assertEquals(0xBB, packet[4].toInt() and 0xFF)
        assertEquals(".well-known", String(packet, 5, 11, Charsets.US_ASCII))
        // The repeat of the same option carries a delta of zero.
        assertEquals(0x04, packet[16].toInt() and 0xFF)
        assertEquals("core", String(packet, 17, 4, Charsets.US_ASCII))
    }

    @Test
    fun `a 2 05 content response is recognised and its payload extracted`() {
        val response = byteArrayOf(0x60, 0x45, 0x12, 0x34, 0xFF.toByte()) +
            "</sensor/temp>;rt=\"temperature\"".toByteArray()
        assertTrue(IotProbes.isCoapContent(response))
        assertEquals("</sensor/temp>;rt=\"temperature\"", IotProbes.coapPayload(response))
    }

    @Test
    fun `a coap error response is not mistaken for content`() {
        // 4.04 Not Found is 0x84.
        assertFalse(IotProbes.isCoapContent(byteArrayOf(0x60, 0x84.toByte(), 0x12, 0x34)))
        assertNull(IotProbes.coapPayload(byteArrayOf(0x60, 0x45, 0x12, 0x34)))
    }

    // ---------------------------------------------------------------- Modbus

    /**
     * Function 0x2B / MEI 0x0E is the only Modbus request this tool builds, because it is the
     * only one that is unambiguously a read of metadata rather than of live process data.
     */
    @Test
    fun `modbus request reads device identification and nothing else`() {
        val packet = IotProbes.modbusDeviceId(transactionId = 0x0102, unitId = 0x11)
        assertEquals("01 02 00 00 00 05 11 2b 0e 01 00", hex(packet))
        assertEquals(0x2B, packet[7].toInt() and 0xFF)
        assertEquals(0x0E, packet[8].toInt() and 0xFF)
    }

    @Test
    fun `modbus identity objects are decoded by their assigned meanings`() {
        val vendor = "Acme".toByteArray()
        val product = "PLC-1".toByteArray()
        val response = byteArrayOf(
            0x00, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x01, // MBAP
            0x2B, 0x0E, 0x01, 0x01, 0x00, // function, MEI, read code, conformity, more follows
            0x02, // two objects
            0x00, vendor.size.toByte(),
        ) + vendor + byteArrayOf(0x01, product.size.toByte()) + product

        val identity = IotProbes.parseModbusDeviceId(response)!!
        assertEquals("Acme", identity["vendor"])
        assertEquals("PLC-1", identity["product_code"])
    }

    @Test
    fun `a modbus response for another function is not decoded as identity`() {
        val response = ByteArray(20).also { it[7] = 0x03 }
        assertNull(IotProbes.parseModbusDeviceId(response))
        assertNull(IotProbes.parseModbusDeviceId(ByteArray(5)))
    }

    // ---------------------------------------------------------------- BACnet

    @Test
    fun `bacnet who-is is a global broadcast unconfirmed request`() {
        val packet = IotProbes.bacnetWhoIs()
        // The canonical Who-Is: four bytes of BVLC, six of NPDU, two of APDU.
        assertEquals("81 0b 00 0c 01 20 ff ff 00 ff 10 08", hex(packet))
        assertEquals(12, packet.size)
        // The BVLC length field must match the real packet length.
        assertEquals(packet.size, ((packet[2].toInt() and 0xFF) shl 8) or (packet[3].toInt() and 0xFF))
    }

    @Test
    fun `an i-am response yields the device instance`() {
        // Object identifier 0xC4 tag, device type (8) in the top ten bits, instance 260001.
        val identifier = (8 shl 22) or 260001
        val response = byteArrayOf(
            0x81.toByte(), 0x0B, 0x00, 0x18,
            0x01, 0x20, 0xFF.toByte(), 0xFF.toByte(), 0x00, 0xFF.toByte(),
            0x10, 0x00, 0xC4.toByte(),
            ((identifier shr 24) and 0xFF).toByte(),
            ((identifier shr 16) and 0xFF).toByte(),
            ((identifier shr 8) and 0xFF).toByte(),
            (identifier and 0xFF).toByte(),
        )
        assertEquals(260001, IotProbes.parseBacnetIAm(response))
    }

    @Test
    fun `a non-bacnet datagram is rejected`() {
        assertNull(IotProbes.parseBacnetIAm(ByteArray(20)))
        assertNull(IotProbes.parseBacnetIAm(byteArrayOf(0x81.toByte(), 0x0B)))
    }

    // ---------------------------------------------------------------- DICOM

    @Test
    fun `dicom associate request proposes only verification`() {
        val packet = IotProbes.dicomAssociateRequest(calledAeTitle = "PACS", callingAeTitle = "PROBE")
        assertEquals(0x01, packet[0].toInt() and 0xFF) // A-ASSOCIATE-RQ
        // The declared length must match what follows the six-byte header.
        val declared = ((packet[2].toInt() and 0xFF) shl 24) or ((packet[3].toInt() and 0xFF) shl 16) or
            ((packet[4].toInt() and 0xFF) shl 8) or (packet[5].toInt() and 0xFF)
        assertEquals(packet.size - 6, declared)

        // AE titles are exactly sixteen bytes, space-padded.
        assertEquals("PACS            ", String(packet, 10, 16, Charsets.US_ASCII))
        assertEquals("PROBE           ", String(packet, 26, 16, Charsets.US_ASCII))

        val body = String(packet, Charsets.ISO_8859_1)
        assertTrue(body.contains("1.2.840.10008.3.1.1.1")) // application context
        assertTrue(body.contains("1.2.840.10008.1.1")) // verification SOP class
    }

    /**
     * Accepting an association from a title the node has never been configured to know is the
     * whole finding, so the two response types must not be confused.
     */
    @Test
    fun `an accepted association is told apart from a rejection`() {
        val accepted = ByteArray(30).also {
            it[0] = 0x02
            "SCP-NODE        ".toByteArray().copyInto(it, 10)
        }
        val result = IotProbes.parseDicomResponse(accepted)
        assertTrue(result is IotProbes.DicomResult.Accepted)
        assertEquals("SCP-NODE", (result as IotProbes.DicomResult.Accepted).respondingAeTitle)

        val rejected = ByteArray(10).also { it[0] = 0x03; it[9] = 0x07 }
        val refusal = IotProbes.parseDicomResponse(rejected)
        assertTrue(refusal is IotProbes.DicomResult.Rejected)
        assertTrue((refusal as IotProbes.DicomResult.Rejected).reason.contains("called AE title"))
    }

    @Test
    fun `an unrecognised dicom pdu returns nothing rather than guessing`() {
        assertNull(IotProbes.parseDicomResponse(ByteArray(0)))
        assertNull(IotProbes.parseDicomResponse(byteArrayOf(0x07, 0x00)))
    }

    // ----------------------------------------------------------------- RTSP

    @Test
    fun `rtsp requests are well-formed and read-only`() {
        val options = String(IotProbes.rtspOptions("10.0.0.5", 554))
        assertTrue(options.startsWith("OPTIONS rtsp://10.0.0.5:554/ RTSP/1.0"))
        assertTrue(options.endsWith("\r\n\r\n"))
        assertTrue(String(IotProbes.rtspDescribe("10.0.0.5", 554)).startsWith("DESCRIBE"))
    }

    @Test
    fun `an unauthenticated stream is told apart from one demanding credentials`() {
        val open = IotProbes.parseRtspResponse(
            "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Hipcam RealServer/V1.0\r\n\r\n",
        )!!
        assertEquals(200, open.status)
        assertFalse(open.requiresAuthentication)
        assertEquals("Hipcam RealServer/V1.0", open.server)

        val guarded = IotProbes.parseRtspResponse("RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\n\r\n")!!
        assertTrue(guarded.requiresAuthentication)
        assertNull(guarded.server)
    }

    @Test
    fun `a non-rtsp response is not parsed`() {
        assertNull(IotProbes.parseRtspResponse("HTTP/1.1 200 OK\r\n\r\n"))
    }
}
