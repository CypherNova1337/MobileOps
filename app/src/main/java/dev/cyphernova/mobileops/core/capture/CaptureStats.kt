package dev.cyphernova.mobileops.core.capture

import java.util.concurrent.atomic.AtomicLong

/**
 * Counters for what the relay actually did with each packet.
 *
 * A capture that produces a small pcap is ambiguous: the device may have been idle, or every
 * connection may have been failing silently. These distinguish the two, which no amount of
 * staring at a packet count can.
 */
class CaptureStats {

    val tcpSynSeen = AtomicLong()
    val tcpEstablished = AtomicLong()
    val tcpProtectFailed = AtomicLong()
    val tcpConnectFailed = AtomicLong()
    val tcpBytesToServer = AtomicLong()
    val tcpBytesToDevice = AtomicLong()

    val udpFlowsOpened = AtomicLong()
    val udpProtectFailed = AtomicLong()
    val udpBytesToServer = AtomicLong()
    val udpBytesToDevice = AtomicLong()

    /** IPv6 is not relayed — the TUN is IPv4-only — so these are seen, logged and dropped. */
    val ipv6Dropped = AtomicLong()

    /** ICMP and anything else that needs a raw socket to forward. */
    val otherProtocolDropped = AtomicLong()

    fun snapshot(): Map<String, Long> = mapOf(
        "tcp_syn_seen" to tcpSynSeen.get(),
        "tcp_established" to tcpEstablished.get(),
        "tcp_protect_failed" to tcpProtectFailed.get(),
        "tcp_connect_failed" to tcpConnectFailed.get(),
        "tcp_bytes_to_server" to tcpBytesToServer.get(),
        "tcp_bytes_to_device" to tcpBytesToDevice.get(),
        "udp_flows" to udpFlowsOpened.get(),
        "udp_protect_failed" to udpProtectFailed.get(),
        "udp_bytes_to_server" to udpBytesToServer.get(),
        "udp_bytes_to_device" to udpBytesToDevice.get(),
        "ipv6_dropped" to ipv6Dropped.get(),
        "other_protocol_dropped" to otherProtocolDropped.get(),
    )

    /**
     * Reads the counters and says what they mean, in the order the failures actually matter —
     * the first true statement is the one worth acting on.
     */
    fun diagnose(): String = when {
        tcpSynSeen.get() == 0L && udpFlowsOpened.get() == 0L && ipv6Dropped.get() == 0L ->
            "No traffic reached the tunnel at all. The device was idle, or the route was not applied."

        tcpProtectFailed.get() > 0 || udpProtectFailed.get() > 0 ->
            "VpnService.protect() refused ${tcpProtectFailed.get() + udpProtectFailed.get()} socket(s). " +
                "Unprotected relay sockets would loop back into the tunnel, so those flows were dropped. " +
                "This is a fatal fault, not a slow network."

        tcpSynSeen.get() > 0 && tcpEstablished.get() == 0L ->
            "${tcpSynSeen.get()} TCP connection attempt(s), none established. The relay is accepting " +
                "SYNs and never completing the far-side connect: apps will hang rather than fail fast."

        ipv6Dropped.get() > tcpSynSeen.get() + udpFlowsOpened.get() ->
            "${ipv6Dropped.get()} IPv6 packet(s) dropped, outnumbering all relayed IPv4 traffic. This " +
                "network is IPv6-first and most traffic is going nowhere; IPv4 fallback is masking it."

        tcpEstablished.get() > 0 && tcpBytesToDevice.get() == 0L ->
            "Connections established but no bytes came back. The far side is connecting and the " +
                "inbound pump is not delivering."

        else ->
            "Relay healthy: ${tcpEstablished.get()} of ${tcpSynSeen.get()} TCP connection(s) established, " +
                "${udpFlowsOpened.get()} UDP flow(s)."
    }
}
