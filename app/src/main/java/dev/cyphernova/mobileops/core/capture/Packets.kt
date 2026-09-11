package dev.cyphernova.mobileops.core.capture

import java.nio.ByteBuffer
import java.nio.ByteOrder

const val PROTO_TCP = 6
const val PROTO_UDP = 17

object TcpFlags {
    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val PSH = 0x08
    const val ACK = 0x10
}

/** An IPv4 packet as read off the TUN interface. */
data class Ip4Packet(
    val sourceIp: Int,
    val destinationIp: Int,
    val protocol: Int,
    val headerLength: Int,
    val totalLength: Int,
    val raw: ByteArray,
) {
    val payloadOffset: Int get() = headerLength
    val payloadLength: Int get() = totalLength - headerLength

    // Data classes compare arrays by reference; identity is the header, so compare that.
    override fun equals(other: Any?): Boolean =
        other is Ip4Packet && sourceIp == other.sourceIp && destinationIp == other.destinationIp &&
            protocol == other.protocol && totalLength == other.totalLength

    override fun hashCode(): Int =
        (((sourceIp * 31 + destinationIp) * 31 + protocol) * 31) + totalLength
}

data class TcpSegment(
    val sourcePort: Int,
    val destinationPort: Int,
    val sequence: Long,
    val acknowledgement: Long,
    val flags: Int,
    val payload: ByteArray,
) {
    val isSyn: Boolean get() = flags and TcpFlags.SYN != 0
    val isAck: Boolean get() = flags and TcpFlags.ACK != 0
    val isFin: Boolean get() = flags and TcpFlags.FIN != 0
    val isRst: Boolean get() = flags and TcpFlags.RST != 0

    override fun equals(other: Any?): Boolean =
        other is TcpSegment && sourcePort == other.sourcePort &&
            destinationPort == other.destinationPort && sequence == other.sequence &&
            flags == other.flags

    override fun hashCode(): Int =
        (((sourcePort * 31 + destinationPort) * 31 + sequence.toInt()) * 31) + flags
}

data class UdpDatagram(
    val sourcePort: Int,
    val destinationPort: Int,
    val payload: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is UdpDatagram && sourcePort == other.sourcePort &&
            destinationPort == other.destinationPort && payload.contentEquals(other.payload)

    override fun hashCode(): Int = (sourcePort * 31 + destinationPort) * 31 + payload.contentHashCode()
}

/**
 * Reads and writes raw IPv4/TCP/UDP. The TUN interface hands over bare IP packets with no link
 * layer, so everything here works on the IP header directly.
 */
object Packets {

    private const val IP4_HEADER_BYTES = 20
    private const val TCP_HEADER_BYTES = 20
    private const val UDP_HEADER_BYTES = 8
    private const val DEFAULT_TTL = 64
    private const val DEFAULT_WINDOW = 65535

    fun parseIp4(buffer: ByteArray, length: Int): Ip4Packet? {
        if (length < IP4_HEADER_BYTES) return null
        val versionAndIhl = buffer[0].toInt() and 0xFF
        if (versionAndIhl shr 4 != 4) return null // IPv6 is not relayed; the TUN is IPv4-only.

        val headerLength = (versionAndIhl and 0x0F) * 4
        if (headerLength < IP4_HEADER_BYTES || headerLength > length) return null

        val view = ByteBuffer.wrap(buffer, 0, length).order(ByteOrder.BIG_ENDIAN)
        val totalLength = view.getShort(2).toInt() and 0xFFFF
        if (totalLength > length || totalLength < headerLength) return null

        return Ip4Packet(
            sourceIp = view.getInt(12),
            destinationIp = view.getInt(16),
            protocol = buffer[9].toInt() and 0xFF,
            headerLength = headerLength,
            totalLength = totalLength,
            raw = buffer,
        )
    }

    fun parseTcp(packet: Ip4Packet): TcpSegment? {
        val offset = packet.payloadOffset
        if (packet.payloadLength < TCP_HEADER_BYTES) return null
        val view = ByteBuffer.wrap(packet.raw).order(ByteOrder.BIG_ENDIAN)

        val dataOffset = ((packet.raw[offset + 12].toInt() and 0xF0) shr 4) * 4
        if (dataOffset < TCP_HEADER_BYTES || dataOffset > packet.payloadLength) return null

        val payloadStart = offset + dataOffset
        val payloadSize = packet.totalLength - payloadStart
        val payload = if (payloadSize > 0) {
            packet.raw.copyOfRange(payloadStart, payloadStart + payloadSize)
        } else {
            ByteArray(0)
        }

        return TcpSegment(
            sourcePort = view.getShort(offset).toInt() and 0xFFFF,
            destinationPort = view.getShort(offset + 2).toInt() and 0xFFFF,
            sequence = view.getInt(offset + 4).toLong() and 0xFFFFFFFFL,
            acknowledgement = view.getInt(offset + 8).toLong() and 0xFFFFFFFFL,
            flags = packet.raw[offset + 13].toInt() and 0xFF,
            payload = payload,
        )
    }

    fun parseUdp(packet: Ip4Packet): UdpDatagram? {
        val offset = packet.payloadOffset
        if (packet.payloadLength < UDP_HEADER_BYTES) return null
        val view = ByteBuffer.wrap(packet.raw).order(ByteOrder.BIG_ENDIAN)

        val udpLength = view.getShort(offset + 4).toInt() and 0xFFFF
        val payloadSize = (udpLength - UDP_HEADER_BYTES)
            .coerceIn(0, packet.totalLength - offset - UDP_HEADER_BYTES)
        val payloadStart = offset + UDP_HEADER_BYTES

        return UdpDatagram(
            sourcePort = view.getShort(offset).toInt() and 0xFFFF,
            destinationPort = view.getShort(offset + 2).toInt() and 0xFFFF,
            payload = packet.raw.copyOfRange(payloadStart, payloadStart + payloadSize),
        )
    }

    /** Builds a complete IPv4+TCP packet with both checksums filled in. */
    fun buildTcp(
        sourceIp: Int,
        destinationIp: Int,
        sourcePort: Int,
        destinationPort: Int,
        sequence: Long,
        acknowledgement: Long,
        flags: Int,
        payload: ByteArray = ByteArray(0),
    ): ByteArray {
        val total = IP4_HEADER_BYTES + TCP_HEADER_BYTES + payload.size
        val buffer = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN)

        writeIp4Header(buffer, sourceIp, destinationIp, PROTO_TCP, total)

        buffer.putShort(sourcePort.toShort())
        buffer.putShort(destinationPort.toShort())
        buffer.putInt(sequence.toInt())
        buffer.putInt(acknowledgement.toInt())
        buffer.put((TCP_HEADER_BYTES / 4 shl 4).toByte()) // data offset, no options
        buffer.put(flags.toByte())
        buffer.putShort(DEFAULT_WINDOW.toShort())
        buffer.putShort(0) // checksum, filled below
        buffer.putShort(0) // urgent pointer
        buffer.put(payload)

        val packet = buffer.array()
        fillIp4Checksum(packet)
        fillTransportChecksum(packet, PROTO_TCP, IP4_HEADER_BYTES, TCP_HEADER_BYTES + payload.size, 16)
        return packet
    }

    /** Builds a complete IPv4+UDP packet with both checksums filled in. */
    fun buildUdp(
        sourceIp: Int,
        destinationIp: Int,
        sourcePort: Int,
        destinationPort: Int,
        payload: ByteArray,
    ): ByteArray {
        val total = IP4_HEADER_BYTES + UDP_HEADER_BYTES + payload.size
        val buffer = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN)

        writeIp4Header(buffer, sourceIp, destinationIp, PROTO_UDP, total)

        buffer.putShort(sourcePort.toShort())
        buffer.putShort(destinationPort.toShort())
        buffer.putShort((UDP_HEADER_BYTES + payload.size).toShort())
        buffer.putShort(0) // checksum, filled below
        buffer.put(payload)

        val packet = buffer.array()
        fillIp4Checksum(packet)
        fillTransportChecksum(packet, PROTO_UDP, IP4_HEADER_BYTES, UDP_HEADER_BYTES + payload.size, 6)
        return packet
    }

    private fun writeIp4Header(
        buffer: ByteBuffer,
        sourceIp: Int,
        destinationIp: Int,
        protocol: Int,
        totalLength: Int,
    ) {
        buffer.put(0x45)                 // IPv4, 5 words of header
        buffer.put(0)                    // DSCP / ECN
        buffer.putShort(totalLength.toShort())
        buffer.putShort(0)               // identification
        buffer.putShort(0x4000.toShort()) // don't fragment
        buffer.put(DEFAULT_TTL.toByte())
        buffer.put(protocol.toByte())
        buffer.putShort(0)               // checksum, filled below
        buffer.putInt(sourceIp)
        buffer.putInt(destinationIp)
    }

    private fun fillIp4Checksum(packet: ByteArray) {
        packet[10] = 0
        packet[11] = 0
        val sum = ones(packet, 0, IP4_HEADER_BYTES, 0L)
        val checksum = fold(sum)
        packet[10] = (checksum shr 8).toByte()
        packet[11] = checksum.toByte()
    }

    /**
     * TCP and UDP checksums cover a pseudo-header of the IP addresses, protocol and segment
     * length as well as the segment itself — which is why they have to be computed after the
     * IP header is in place.
     */
    private fun fillTransportChecksum(
        packet: ByteArray,
        protocol: Int,
        offset: Int,
        length: Int,
        checksumOffset: Int,
    ) {
        packet[offset + checksumOffset] = 0
        packet[offset + checksumOffset + 1] = 0

        var sum = 0L
        sum += ones(packet, 12, 4, 0L)   // source address
        sum += ones(packet, 16, 4, 0L)   // destination address
        sum += protocol.toLong()
        sum += length.toLong()
        sum = ones(packet, offset, length, sum)

        val checksum = fold(sum)
        packet[offset + checksumOffset] = (checksum shr 8).toByte()
        packet[offset + checksumOffset + 1] = checksum.toByte()
    }

    /** Sums 16-bit big-endian words, padding a trailing odd byte with zero. */
    private fun ones(data: ByteArray, offset: Int, length: Int, initial: Long): Long {
        var sum = initial
        var index = offset
        val end = offset + length - 1
        while (index < end) {
            sum += ((data[index].toInt() and 0xFF) shl 8) or (data[index + 1].toInt() and 0xFF)
            index += 2
        }
        if (length % 2 == 1) {
            sum += (data[end].toInt() and 0xFF) shl 8
        }
        return sum
    }

    private fun fold(sum: Long): Int {
        var value = sum
        while (value shr 16 != 0L) {
            value = (value and 0xFFFF) + (value shr 16)
        }
        return (value.inv() and 0xFFFF).toInt()
    }

    fun ipToString(address: Int): String =
        "${(address shr 24) and 0xFF}.${(address shr 16) and 0xFF}." +
            "${(address shr 8) and 0xFF}.${address and 0xFF}"

    fun stringToIp(address: String): Int {
        val octets = address.split('.')
        require(octets.size == 4) { "not an IPv4 address: $address" }
        return octets.fold(0) { acc, octet -> (acc shl 8) or (octet.toInt() and 0xFF) }
    }
}
