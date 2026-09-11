package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.capture.PROTO_TCP
import dev.cyphernova.mobileops.core.capture.PROTO_UDP
import dev.cyphernova.mobileops.core.capture.Packets
import dev.cyphernova.mobileops.core.capture.TcpFlags
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketsTest {

    private val client = Packets.stringToIp("10.28.14.2")
    private val server = Packets.stringToIp("93.184.216.34")

    /**
     * A one's-complement checksum has the property that summing the data *including* the
     * checksum field yields 0xFFFF. That is exactly what a receiving stack checks, so verifying
     * it here is equivalent to asking whether the far end would accept our packet.
     */
    private fun onesSum(data: ByteArray, offset: Int, length: Int, initial: Long = 0): Long {
        var sum = initial
        var index = offset
        val end = offset + length - 1
        while (index < end) {
            sum += ((data[index].toInt() and 0xFF) shl 8) or (data[index + 1].toInt() and 0xFF)
            index += 2
        }
        if (length % 2 == 1) sum += (data[end].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum
    }

    private fun assertIpChecksumValid(packet: ByteArray) {
        assertEquals("IPv4 header checksum", 0xFFFFL, onesSum(packet, 0, 20))
    }

    private fun assertTransportChecksumValid(packet: ByteArray, protocol: Int) {
        val segmentLength = packet.size - 20
        var sum = onesSum(packet, 12, 4)              // source address
        sum = onesSum(packet, 16, 4, sum)             // destination address
        sum += protocol.toLong()
        sum += segmentLength.toLong()
        sum = onesSum(packet, 20, segmentLength, sum)
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        assertEquals("transport checksum", 0xFFFFL, sum)
    }

    @Test
    fun `tcp packet round trips through the parser`() {
        val payload = "GET / HTTP/1.1\r\n\r\n".toByteArray()
        val packet = Packets.buildTcp(
            sourceIp = server,
            destinationIp = client,
            sourcePort = 443,
            destinationPort = 51234,
            sequence = 0x11223344L,
            acknowledgement = 0x55667788L,
            flags = TcpFlags.PSH or TcpFlags.ACK,
            payload = payload,
        )

        val ip = Packets.parseIp4(packet, packet.size)!!
        assertEquals(server, ip.sourceIp)
        assertEquals(client, ip.destinationIp)
        assertEquals(PROTO_TCP, ip.protocol)
        assertEquals(packet.size, ip.totalLength)

        val tcp = Packets.parseTcp(ip)!!
        assertEquals(443, tcp.sourcePort)
        assertEquals(51234, tcp.destinationPort)
        assertEquals(0x11223344L, tcp.sequence)
        assertEquals(0x55667788L, tcp.acknowledgement)
        assertTrue(tcp.isAck)
        assertArrayEquals(payload, tcp.payload)
    }

    @Test
    fun `tcp checksums are valid`() {
        val packet = Packets.buildTcp(
            server, client, 80, 40000, 1L, 2L,
            TcpFlags.PSH or TcpFlags.ACK, ByteArray(37) { it.toByte() },
        )
        assertIpChecksumValid(packet)
        assertTransportChecksumValid(packet, PROTO_TCP)
    }

    @Test
    fun `odd length payloads still checksum correctly`() {
        // The trailing-byte padding path is the classic place a checksum implementation breaks.
        listOf(1, 3, 15, 101).forEach { size ->
            val packet = Packets.buildTcp(
                server, client, 80, 40000, 1L, 2L, TcpFlags.ACK, ByteArray(size) { 0xAB.toByte() },
            )
            assertIpChecksumValid(packet)
            assertTransportChecksumValid(packet, PROTO_TCP)
        }
    }

    @Test
    fun `syn ack carries no payload and sets both flags`() {
        val packet = Packets.buildTcp(
            server, client, 443, 51234, 999L, 1000L, TcpFlags.SYN or TcpFlags.ACK,
        )
        val tcp = Packets.parseTcp(Packets.parseIp4(packet, packet.size)!!)!!
        assertTrue(tcp.isSyn)
        assertTrue(tcp.isAck)
        assertEquals(0, tcp.payload.size)
        assertIpChecksumValid(packet)
        assertTransportChecksumValid(packet, PROTO_TCP)
    }

    @Test
    fun `udp packet round trips and checksums`() {
        val payload = ByteArray(53) { (it * 7).toByte() }
        val packet = Packets.buildUdp(client, server, 51000, 53, payload)

        val ip = Packets.parseIp4(packet, packet.size)!!
        assertEquals(PROTO_UDP, ip.protocol)

        val udp = Packets.parseUdp(ip)!!
        assertEquals(51000, udp.sourcePort)
        assertEquals(53, udp.destinationPort)
        assertArrayEquals(payload, udp.payload)

        assertIpChecksumValid(packet)
        assertTransportChecksumValid(packet, PROTO_UDP)
    }

    @Test
    fun `empty udp payload is handled`() {
        val packet = Packets.buildUdp(client, server, 51000, 53, ByteArray(0))
        val udp = Packets.parseUdp(Packets.parseIp4(packet, packet.size)!!)!!
        assertEquals(0, udp.payload.size)
        assertTransportChecksumValid(packet, PROTO_UDP)
    }

    @Test
    fun `rejects a non-ipv4 packet`() {
        val ipv6 = ByteArray(40).also { it[0] = 0x60 }
        assertNull(Packets.parseIp4(ipv6, ipv6.size))
    }

    @Test
    fun `rejects a truncated packet`() {
        assertNull(Packets.parseIp4(ByteArray(8), 8))
    }

    @Test
    fun `rejects a packet claiming more length than was read`() {
        val packet = Packets.buildTcp(server, client, 80, 40000, 1L, 2L, TcpFlags.ACK)
        // Claim 400 bytes of total length in a buffer that only holds 40.
        packet[2] = 0x01
        packet[3] = 0x90.toByte()
        assertNull(Packets.parseIp4(packet, packet.size))
    }

    @Test
    fun `address conversion round trips`() {
        listOf("0.0.0.0", "10.28.14.2", "192.168.1.1", "255.255.255.255").forEach { address ->
            assertEquals(address, Packets.ipToString(Packets.stringToIp(address)))
        }
    }

    @Test
    fun `high addresses survive the signed int round trip`() {
        // 255.x addresses set the sign bit; a naive implementation prints a negative octet.
        assertEquals("255.254.253.252", Packets.ipToString(Packets.stringToIp("255.254.253.252")))
    }
}
