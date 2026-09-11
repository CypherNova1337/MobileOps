package dev.cyphernova.mobileops.core.iot

/**
 * Read-only protocol probes that make a device say what it is.
 *
 * An open port is a guess; a protocol answering in its own language is a fact. Each probe here
 * is the smallest legal exchange that produces an identification — the equivalent of saying
 * hello — and every one of them was chosen because the protocol defines it as a read.
 *
 * That restriction is not squeamishness. These protocols mostly predate the idea that a stranger
 * might speak them, and several will happily accept a write from anyone who asks: Modbus will
 * set a coil, BACnet will write a setpoint, DICOM will accept a study. On a site where those
 * control a chiller, a room's pressure differential or an infusion, a write issued to see what
 * happens is not a test result. So the encoders below cannot express one — there is no write
 * path in this file to reach for under time pressure.
 *
 * Encoding and parsing are separated from the sockets so the wire formats can be tested without
 * a network, which for protocols this fiddly is the only way to trust them.
 */
object IotProbes {

    // ---------------------------------------------------------------- MQTT

    /**
     * A CONNECT packet with no credentials.
     *
     * The question it asks is whether the broker accepts anonymous clients, which is the single
     * most common IoT misconfiguration: an anonymous client that can subscribe to `#` receives
     * the whole estate's traffic.
     */
    fun mqttConnect(clientId: String = "mobileops"): ByteArray {
        val id = clientId.toByteArray(Charsets.US_ASCII)
        val payload = byteArrayOf(((id.size shr 8) and 0xFF).toByte(), (id.size and 0xFF).toByte()) + id
        val variableHeader = byteArrayOf(
            0x00, 0x04, 'M'.code.toByte(), 'Q'.code.toByte(), 'T'.code.toByte(), 'T'.code.toByte(),
            0x04, // protocol level 4 = MQTT 3.1.1
            0x02, // clean session, no will, no credentials
            0x00, 0x3C, // keepalive, 60s
        )
        val body = variableHeader + payload
        return byteArrayOf(0x10) + remainingLength(body.size) + body
    }

    /** What a broker said about an anonymous connection. */
    data class MqttResult(val accepted: Boolean, val returnCode: Int, val meaning: String)

    fun parseMqttConnack(response: ByteArray): MqttResult? {
        if (response.size < 4) return null
        if ((response[0].toInt() and 0xF0) != 0x20) return null
        val code = response[3].toInt() and 0xFF
        return MqttResult(
            accepted = code == 0,
            returnCode = code,
            meaning = when (code) {
                0 -> "accepted without credentials"
                1 -> "refused: protocol version unacceptable"
                2 -> "refused: client identifier rejected"
                3 -> "refused: broker unavailable"
                4 -> "refused: bad username or password"
                5 -> "refused: not authorised"
                else -> "refused with code $code"
            },
        )
    }

    /** MQTT's variable-length integer: seven bits a byte, high bit as the continuation flag. */
    fun remainingLength(value: Int): ByteArray {
        var remaining = value
        val bytes = mutableListOf<Byte>()
        do {
            var digit = remaining % 128
            remaining /= 128
            if (remaining > 0) digit = digit or 0x80
            bytes += digit.toByte()
        } while (remaining > 0)
        return bytes.toByteArray()
    }

    // ---------------------------------------------------------------- CoAP

    /**
     * `GET /.well-known/core`, the resource directory every CoAP device is expected to serve.
     *
     * It is readable without authentication by design, so this is identification rather than
     * bypass — but the list it returns is a map of everything the device exposes.
     */
    fun coapWellKnownCore(messageId: Int = 1): ByteArray {
        val header = byteArrayOf(
            0x40, // version 1, confirmable, zero-length token
            0x01, // code 0.01 GET
            ((messageId shr 8) and 0xFF).toByte(),
            (messageId and 0xFF).toByte(),
        )
        val first = ".well-known".toByteArray(Charsets.US_ASCII)
        val second = "core".toByteArray(Charsets.US_ASCII)
        // Uri-Path is option 11. The first carries a delta of 11 from zero; the second repeats
        // the same option, so its delta is zero.
        return header +
            byteArrayOf((((11 shl 4) or first.size) and 0xFF).toByte()) + first +
            byteArrayOf((second.size and 0xFF).toByte()) + second
    }

    /** True where the response is a CoAP 2.05 Content, which means the directory came back. */
    fun isCoapContent(response: ByteArray): Boolean =
        response.size >= 4 && (response[1].toInt() and 0xFF) == 0x45

    fun coapPayload(response: ByteArray): String? {
        // The payload follows a 0xFF marker; everything before it is options.
        val marker = response.indexOfFirst { it == 0xFF.toByte() }
        if (marker < 0 || marker + 1 >= response.size) return null
        return String(response, marker + 1, response.size - marker - 1, Charsets.UTF_8)
    }

    // ---------------------------------------------------------------- Modbus

    /**
     * Read Device Identification — function 0x2B, MEI type 0x0E.
     *
     * The one Modbus request that is unambiguously a read of metadata rather than of process
     * data, and the only one this file will build. It returns vendor, product code and revision.
     */
    fun modbusDeviceId(transactionId: Int = 1, unitId: Int = 1): ByteArray {
        val pdu = byteArrayOf(
            0x2B, // Encapsulated Interface Transport
            0x0E, // Read Device Identification
            0x01, // basic identification
            0x00, // start at object 0
        )
        val length = pdu.size + 1
        return byteArrayOf(
            ((transactionId shr 8) and 0xFF).toByte(), (transactionId and 0xFF).toByte(),
            0x00, 0x00, // protocol identifier, always zero for Modbus/TCP
            ((length shr 8) and 0xFF).toByte(), (length and 0xFF).toByte(),
            (unitId and 0xFF).toByte(),
        ) + pdu
    }

    /** Vendor, product and revision as a Modbus device reports them. */
    fun parseModbusDeviceId(response: ByteArray): Map<String, String>? {
        // MBAP is seven bytes; the PDU follows.
        if (response.size < 14) return null
        if ((response[7].toInt() and 0xFF) != 0x2B) return null
        val objectCount = response[12].toInt() and 0xFF
        var offset = 13
        val labels = listOf("vendor", "product_code", "revision", "vendor_url", "product_name")
        val values = mutableMapOf<String, String>()
        repeat(objectCount) {
            if (offset + 2 > response.size) return@repeat
            val id = response[offset].toInt() and 0xFF
            val length = response[offset + 1].toInt() and 0xFF
            offset += 2
            if (offset + length > response.size) return@repeat
            val value = String(response, offset, length, Charsets.US_ASCII)
            values[labels.getOrElse(id) { "object_$id" }] = value
            offset += length
        }
        return values.ifEmpty { null }
    }

    // ---------------------------------------------------------------- BACnet

    /**
     * A Who-Is broadcast, which every BACnet device answers with an I-Am naming itself.
     *
     * BVLC header, then an NPDU addressed to the global broadcast network, then a two-byte
     * unconfirmed-request APDU. There is nothing to authenticate against — this is what the
     * protocol does.
     */
    fun bacnetWhoIs(): ByteArray {
        val npdu = byteArrayOf(
            0x01, // protocol version
            0x20, // control: destination specifier present
            0xFF.toByte(), 0xFF.toByte(), // DNET 0xFFFF, the global broadcast
            0x00, // DLEN zero, meaning broadcast on that network
            0xFF.toByte(), // hop count
        )
        val apdu = byteArrayOf(0x10, 0x08) // unconfirmed request, Who-Is
        val length = 4 + npdu.size + apdu.size
        return byteArrayOf(
            0x81.toByte(), // BVLC for BACnet/IP
            0x0B, // Original-Broadcast-NPDU
            ((length shr 8) and 0xFF).toByte(), (length and 0xFF).toByte(),
        ) + npdu + apdu
    }

    /** The device instance number out of an I-Am, which names the device on the BACnet network. */
    fun parseBacnetIAm(response: ByteArray): Int? {
        if (response.size < 12) return null
        if ((response[0].toInt() and 0xFF) != 0x81) return null
        // Find the unconfirmed I-Am APDU, then its object identifier tag.
        val apdu = response.indexOfFirst { it == 0x10.toByte() }
        if (apdu < 0 || apdu + 6 >= response.size) return null
        if ((response[apdu + 1].toInt() and 0xFF) != 0x00) return null // service choice 0 = I-Am
        if ((response[apdu + 2].toInt() and 0xFF) != 0xC4) return null // application tag, object id
        val identifier = ((response[apdu + 3].toInt() and 0xFF) shl 24) or
            ((response[apdu + 4].toInt() and 0xFF) shl 16) or
            ((response[apdu + 5].toInt() and 0xFF) shl 8) or
            (response[apdu + 6].toInt() and 0xFF)
        // The top ten bits are the object type; the instance is the low twenty-two.
        return identifier and 0x3FFFFF
    }

    // ---------------------------------------------------------------- DICOM

    /**
     * An A-ASSOCIATE-RQ proposing only the Verification service — a DICOM ping.
     *
     * The finding it produces is about who the node will talk to. DICOM's default access control
     * is the calling AE title, which is a name the caller chooses for itself, so an association
     * accepted from an arbitrary title means the node's only gate is one the caller controls.
     */
    fun dicomAssociateRequest(
        calledAeTitle: String = "ANY-SCP",
        callingAeTitle: String = "MOBILEOPS",
    ): ByteArray {
        val applicationContext = dicomItem(0x10, DICOM_APPLICATION_CONTEXT)
        val presentationContext = dicomItem(
            0x20,
            byteArrayOf(0x01, 0x00, 0x00, 0x00) +
                dicomItem(0x30, VERIFICATION_SOP_CLASS) +
                dicomItem(0x40, IMPLICIT_VR_LITTLE_ENDIAN),
        )
        val userInformation = dicomItem(
            0x50,
            // Maximum PDU length sub-item: 16384 bytes.
            dicomItem(0x51, byteArrayOf(0x00, 0x00, 0x40, 0x00)),
        )

        val body = byteArrayOf(0x00, 0x01, 0x00, 0x00) +
            aeTitle(calledAeTitle) + aeTitle(callingAeTitle) + ByteArray(32) +
            applicationContext + presentationContext + userInformation

        return byteArrayOf(0x01, 0x00) + beInt(body.size) + body
    }

    /** What the node made of an association proposed by a caller it has never met. */
    sealed interface DicomResult {
        data class Accepted(val respondingAeTitle: String) : DicomResult
        data class Rejected(val reason: String) : DicomResult
    }

    fun parseDicomResponse(response: ByteArray): DicomResult? = when {
        response.isEmpty() -> null

        // A-ASSOCIATE-AC: the node accepted an association from a title it has never seen.
        (response[0].toInt() and 0xFF) == 0x02 && response.size >= 26 ->
            DicomResult.Accepted(String(response, 10, 16, Charsets.US_ASCII).trim())

        // A-ASSOCIATE-RJ: the reason byte says whether it was the title or the service.
        (response[0].toInt() and 0xFF) == 0x03 && response.size >= 10 ->
            DicomResult.Rejected(dicomRejectReason(response[9].toInt() and 0xFF))

        else -> null
    }

    private fun dicomRejectReason(code: Int): String = when (code) {
        1 -> "no reason given"
        2 -> "application context not supported"
        3 -> "calling AE title not recognised"
        7 -> "called AE title not recognised"
        else -> "reason code $code"
    }

    private fun dicomItem(type: Int, content: ByteArray): ByteArray = byteArrayOf(
        (type and 0xFF).toByte(),
        0x00,
        ((content.size shr 8) and 0xFF).toByte(),
        (content.size and 0xFF).toByte(),
    ) + content

    /** AE titles are exactly sixteen bytes, space-padded. */
    private fun aeTitle(value: String): ByteArray {
        val bytes = ByteArray(16) { ' '.code.toByte() }
        value.take(16).toByteArray(Charsets.US_ASCII).copyInto(bytes)
        return bytes
    }

    private fun beInt(value: Int) = byteArrayOf(
        ((value shr 24) and 0xFF).toByte(),
        ((value shr 16) and 0xFF).toByte(),
        ((value shr 8) and 0xFF).toByte(),
        (value and 0xFF).toByte(),
    )

    private val DICOM_APPLICATION_CONTEXT = "1.2.840.10008.3.1.1.1".toByteArray(Charsets.US_ASCII)
    private val VERIFICATION_SOP_CLASS = "1.2.840.10008.1.1".toByteArray(Charsets.US_ASCII)
    private val IMPLICIT_VR_LITTLE_ENDIAN = "1.2.840.10008.1.2".toByteArray(Charsets.US_ASCII)

    // ---------------------------------------------------------------- RTSP

    /** An OPTIONS request, which is how a stream says whether it wants credentials. */
    fun rtspOptions(host: String, port: Int): ByteArray =
        ("OPTIONS rtsp://$host:$port/ RTSP/1.0\r\n" +
            "CSeq: 1\r\n" +
            "User-Agent: MobileOps\r\n\r\n").toByteArray(Charsets.US_ASCII)

    /** A DESCRIBE, which returns the stream description where one is readable unauthenticated. */
    fun rtspDescribe(host: String, port: Int, path: String = "/"): ByteArray =
        ("DESCRIBE rtsp://$host:$port$path RTSP/1.0\r\n" +
            "CSeq: 2\r\n" +
            "Accept: application/sdp\r\n" +
            "User-Agent: MobileOps\r\n\r\n").toByteArray(Charsets.US_ASCII)

    data class RtspResult(val status: Int, val requiresAuthentication: Boolean, val server: String?)

    fun parseRtspResponse(response: String): RtspResult? {
        val status = Regex("""RTSP/1\.0 (\d{3})""").find(response)?.groupValues?.get(1)?.toIntOrNull()
            ?: return null
        return RtspResult(
            status = status,
            requiresAuthentication = status == 401,
            server = Regex("""(?i)^Server:\s*(.+)$""", RegexOption.MULTILINE)
                .find(response)?.groupValues?.get(1)?.trim(),
        )
    }
}
