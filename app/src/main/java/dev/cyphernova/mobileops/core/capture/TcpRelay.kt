package dev.cyphernova.mobileops.core.capture

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentHashMap
import kotlin.random.Random

/**
 * A userspace TCP endpoint for traffic coming off the TUN.
 *
 * The device's TCP stack thinks it is talking to the real server; in fact it is talking to us,
 * and we hold a separate real socket to that server and shuttle bytes between the two. That
 * indirection is what makes capture possible without root — and it is why this has to speak
 * enough TCP to be convincing.
 *
 * Deliberately minimal: no retransmission, no congestion control, no window scaling, no options.
 * The client side of every connection is a loopback-speed TUN where nothing is ever dropped, so
 * the machinery that exists to cope with a lossy path has nothing to do. Loss on the real
 * network is handled by the kernel on the far socket, which is a full TCP implementation.
 */
class TcpRelay(
    private val scope: CoroutineScope,
    private val protect: (Socket) -> Boolean,
    private val emit: (ByteArray) -> Unit,
) {

    private enum class State { CONNECTING, ESTABLISHED, CLOSING }

    private class Connection(
        val key: FlowKey,
        val outbound: Channel<ByteArray>,
    ) {
        @Volatile var channel: SocketChannel? = null
        @Volatile var state: State = State.CONNECTING

        /** Next sequence number we will put on the wire toward the device. */
        @Volatile var ourSequence: Long = 0

        /** Next sequence number we expect from the device. */
        @Volatile var theirSequence: Long = 0

        val jobs = mutableListOf<Job>()
    }

    private val connections = ConcurrentHashMap<FlowKey, Connection>()

    val activeFlows: Int get() = connections.size

    fun handle(packet: Ip4Packet, segment: TcpSegment) {
        val key = FlowKey(
            sourceIp = packet.sourceIp,
            sourcePort = segment.sourcePort,
            destinationIp = packet.destinationIp,
            destinationPort = segment.destinationPort,
        )

        val existing = connections[key]

        when {
            segment.isRst -> close(key)

            segment.isSyn && existing == null -> open(key, segment)

            existing == null -> {
                // Mid-stream packet for a flow we know nothing about (we were started after the
                // connection was). Tell the device to give up rather than let it hang.
                emit(reset(key, segment))
            }

            segment.isFin -> {
                existing.theirSequence = seqAdd(segment.sequence, segment.payload.size + 1)
                emit(ack(existing))
                emit(finAck(existing))
                existing.state = State.CLOSING
                close(key)
            }

            segment.payload.isNotEmpty() -> {
                existing.theirSequence = seqAdd(segment.sequence, segment.payload.size)
                emit(ack(existing))
                existing.outbound.trySend(segment.payload)
            }
        }
    }

    private fun open(key: FlowKey, syn: TcpSegment) {
        val connection = Connection(key, Channel(Channel.BUFFERED))
        if (connections.putIfAbsent(key, connection) != null) return

        connection.ourSequence = Random.nextLong(0, 0xFFFFFFFFL)
        connection.theirSequence = seqAdd(syn.sequence, 1)

        val job = scope.launch(Dispatchers.IO) {
            val channel = runCatching {
                SocketChannel.open().also { it.configureBlocking(true) }
            }.getOrNull()

            if (channel == null || !protect(channel.socket())) {
                runCatching { channel?.close() }
                emit(reset(key, syn))
                connections.remove(key)
                return@launch
            }

            val connected = runCatching {
                channel.connect(
                    InetSocketAddress(Packets.ipToString(key.destinationIp), key.destinationPort),
                )
            }.getOrDefault(false)

            if (!connected) {
                runCatching { channel.close() }
                emit(reset(key, syn))
                connections.remove(key)
                return@launch
            }

            connection.channel = channel

            // The handshake completes only once the real connection is up, so a refused
            // connection surfaces to the app as a refusal rather than a silent hang.
            emit(
                Packets.buildTcp(
                    sourceIp = key.destinationIp,
                    destinationIp = key.sourceIp,
                    sourcePort = key.destinationPort,
                    destinationPort = key.sourcePort,
                    sequence = connection.ourSequence,
                    acknowledgement = connection.theirSequence,
                    flags = TcpFlags.SYN or TcpFlags.ACK,
                ),
            )
            connection.ourSequence = seqAdd(connection.ourSequence, 1)
            connection.state = State.ESTABLISHED

            connection.jobs += scope.launch(Dispatchers.IO) { pumpOutbound(connection, channel) }
            connection.jobs += scope.launch(Dispatchers.IO) { pumpInbound(connection, channel) }
        }
        connection.jobs += job
    }

    /** Device → server. A dedicated writer keeps segment order intact under concurrent arrivals. */
    private suspend fun pumpOutbound(connection: Connection, channel: SocketChannel) {
        for (payload in connection.outbound) {
            val written = runCatching {
                val buffer = ByteBuffer.wrap(payload)
                while (buffer.hasRemaining()) channel.write(buffer)
                true
            }.getOrDefault(false)
            if (!written) break
        }
        close(connection.key)
    }

    /** Server → device. Each read becomes one segment carrying our current sequence number. */
    private suspend fun pumpInbound(connection: Connection, channel: SocketChannel) {
        val buffer = ByteBuffer.allocate(SEGMENT_BYTES)
        while (scope.isActive && connection.state == State.ESTABLISHED) {
            buffer.clear()
            val read = runCatching { channel.read(buffer) }.getOrElse { -1 }
            if (read <= 0) break

            val payload = ByteArray(read).also {
                buffer.flip()
                buffer.get(it)
            }
            emit(
                Packets.buildTcp(
                    sourceIp = connection.key.destinationIp,
                    destinationIp = connection.key.sourceIp,
                    sourcePort = connection.key.destinationPort,
                    destinationPort = connection.key.sourcePort,
                    sequence = connection.ourSequence,
                    acknowledgement = connection.theirSequence,
                    flags = TcpFlags.PSH or TcpFlags.ACK,
                    payload = payload,
                ),
            )
            connection.ourSequence = seqAdd(connection.ourSequence, read)
        }

        // The far end hung up: pass the close through so the app sees a clean EOF.
        if (connection.state == State.ESTABLISHED) {
            connection.state = State.CLOSING
            emit(finAck(connection))
        }
        close(connection.key)
    }

    private fun ack(connection: Connection) = Packets.buildTcp(
        sourceIp = connection.key.destinationIp,
        destinationIp = connection.key.sourceIp,
        sourcePort = connection.key.destinationPort,
        destinationPort = connection.key.sourcePort,
        sequence = connection.ourSequence,
        acknowledgement = connection.theirSequence,
        flags = TcpFlags.ACK,
    )

    private fun finAck(connection: Connection) = Packets.buildTcp(
        sourceIp = connection.key.destinationIp,
        destinationIp = connection.key.sourceIp,
        sourcePort = connection.key.destinationPort,
        destinationPort = connection.key.sourcePort,
        sequence = connection.ourSequence,
        acknowledgement = connection.theirSequence,
        flags = TcpFlags.FIN or TcpFlags.ACK,
    )

    private fun reset(key: FlowKey, segment: TcpSegment) = Packets.buildTcp(
        sourceIp = key.destinationIp,
        destinationIp = key.sourceIp,
        sourcePort = key.destinationPort,
        destinationPort = key.sourcePort,
        sequence = segment.acknowledgement,
        acknowledgement = seqAdd(segment.sequence, 1),
        flags = TcpFlags.RST or TcpFlags.ACK,
    )

    fun close(key: FlowKey) {
        connections.remove(key)?.let { connection ->
            connection.outbound.close()
            connection.jobs.forEach { it.cancel() }
            runCatching { connection.channel?.close() }
        }
    }

    fun closeAll() {
        connections.keys.toList().forEach(::close)
    }

    private companion object {
        const val SEGMENT_BYTES = 1400 // stays under a 1500-byte MTU once headers are added

        /** Sequence numbers are 32-bit and wrap; every advance has to wrap with them. */
        fun seqAdd(sequence: Long, delta: Int): Long = (sequence + delta) and 0xFFFFFFFFL
    }
}
