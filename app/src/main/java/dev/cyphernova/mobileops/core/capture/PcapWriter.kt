package dev.cyphernova.mobileops.core.capture

import java.io.BufferedOutputStream
import java.io.Closeable
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Writes classic libpcap files that Wireshark and tcpdump open directly.
 *
 * Link type is RAW (101): the TUN interface hands over bare IPv4 packets with no Ethernet
 * header, so claiming EN10MB would make every packet unparseable.
 */
class PcapWriter(private val file: File, private val snapLength: Int = 65535) : Closeable {

    private val stream = BufferedOutputStream(FileOutputStream(file))
    private var packets = 0L
    private var bytes = 0L

    val packetCount: Long get() = packets
    val byteCount: Long get() = bytes
    val path: String get() = file.absolutePath

    init {
        val header = ByteBuffer.allocate(24).order(ByteOrder.BIG_ENDIAN)
        header.putInt(MAGIC)
        header.putShort(2)               // version major
        header.putShort(4)               // version minor
        header.putInt(0)                 // GMT offset
        header.putInt(0)                 // timestamp accuracy
        header.putInt(snapLength)
        header.putInt(LINKTYPE_RAW)
        stream.write(header.array())
        stream.flush()
    }

    @Synchronized
    fun write(packet: ByteArray, length: Int = packet.size) {
        val captured = minOf(length, snapLength)
        val now = System.currentTimeMillis()

        val record = ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN)
        record.putInt((now / 1000).toInt())
        record.putInt(((now % 1000) * 1000).toInt())
        record.putInt(captured)
        record.putInt(length) // original length, so truncation is visible to the reader
        stream.write(record.array())
        stream.write(packet, 0, captured)

        packets++
        bytes += length
        // Flushed per packet: a capture killed by the system is still a readable pcap.
        stream.flush()
    }

    override fun close() {
        runCatching { stream.flush() }
        runCatching { stream.close() }
    }

    private companion object {
        const val MAGIC = 0xA1B2C3D4.toInt()
        const val LINKTYPE_RAW = 101
    }
}
