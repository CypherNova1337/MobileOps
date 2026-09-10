package dev.cyphernova.mobileops.core.capture

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.util.concurrent.ConcurrentHashMap

/**
 * Forwards UDP out of the TUN and relays replies back.
 *
 * Each flow gets its own socket, protected from the VPN route so it egresses on the real network
 * rather than looping back into our own interface.
 */
class UdpRelay(
    private val scope: CoroutineScope,
    private val protect: (DatagramSocket) -> Boolean,
    private val emit: (ByteArray) -> Unit,
    private val stats: CaptureStats = CaptureStats(),
) {

    private class Flow(val channel: DatagramChannel, val job: Job) {
        @Volatile var lastActiveMs: Long = System.currentTimeMillis()
    }

    private val flows = ConcurrentHashMap<FlowKey, Flow>()

    fun handle(packet: Ip4Packet, datagram: UdpDatagram) {
        val key = FlowKey(
            sourceIp = packet.sourceIp,
            sourcePort = datagram.sourcePort,
            destinationIp = packet.destinationIp,
            destinationPort = datagram.destinationPort,
        )

        val flow = flows[key] ?: openFlow(key) ?: return
        flow.lastActiveMs = System.currentTimeMillis()

        scope.launch(Dispatchers.IO) {
            runCatching {
                flow.channel.write(ByteBuffer.wrap(datagram.payload))
                stats.udpBytesToServer.addAndGet(datagram.payload.size.toLong())
            }.onFailure { close(key) }
        }
    }

    private fun openFlow(key: FlowKey): Flow? {
        val channel = runCatching { DatagramChannel.open() }.getOrNull() ?: return null

        if (!protect(channel.socket())) {
            stats.udpProtectFailed.incrementAndGet()
            runCatching { channel.close() }
            return null
        }

        val connected = runCatching {
            channel.connect(
                InetSocketAddress(Packets.ipToString(key.destinationIp), key.destinationPort),
            )
            channel.configureBlocking(true)
        }.isSuccess

        if (!connected) {
            runCatching { channel.close() }
            return null
        }

        val job = scope.launch(Dispatchers.IO) {
            val buffer = ByteBuffer.allocate(MAX_DATAGRAM)
            while (isActive) {
                buffer.clear()
                val read = runCatching { channel.read(buffer) }.getOrElse { -1 }
                if (read <= 0) break

                val payload = ByteArray(read).also {
                    buffer.flip()
                    buffer.get(it)
                }
                stats.udpBytesToDevice.addAndGet(read.toLong())
                // Reply travels back the other way: their port becomes the source.
                emit(
                    Packets.buildUdp(
                        sourceIp = key.destinationIp,
                        destinationIp = key.sourceIp,
                        sourcePort = key.destinationPort,
                        destinationPort = key.sourcePort,
                        payload = payload,
                    ),
                )
                flows[key]?.lastActiveMs = System.currentTimeMillis()
            }
            close(key)
        }

        stats.udpFlowsOpened.incrementAndGet()
        val flow = Flow(channel, job)
        // Another packet for the same flow may have raced us here; keep whichever landed first.
        val existing = flows.putIfAbsent(key, flow)
        if (existing != null) {
            job.cancel()
            runCatching { channel.close() }
            return existing
        }
        return flow
    }

    /** UDP has no teardown, so idle flows are reaped on a timer. */
    fun evictIdle(now: Long = System.currentTimeMillis()) {
        flows.entries
            .filter { now - it.value.lastActiveMs > IDLE_TIMEOUT_MS }
            .forEach { close(it.key) }
    }

    fun close(key: FlowKey) {
        flows.remove(key)?.let { flow ->
            flow.job.cancel()
            runCatching { flow.channel.close() }
        }
    }

    fun closeAll() {
        flows.keys.toList().forEach(::close)
    }

    val activeFlows: Int get() = flows.size

    private companion object {
        const val MAX_DATAGRAM = 32_767
        const val IDLE_TIMEOUT_MS = 60_000L
    }
}
