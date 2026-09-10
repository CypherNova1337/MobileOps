package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.capture.CaptureStats
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CaptureStatsTest {

    @Test
    fun `silence is reported as no traffic rather than a fault`() {
        assertTrue(CaptureStats().diagnose().contains("No traffic reached the tunnel"))
    }

    @Test
    fun `a protect failure outranks everything else`() {
        // Unprotected sockets loop back into the tunnel, so this is fatal and must not be
        // masked by whatever else the counters say.
        val stats = CaptureStats().apply {
            tcpSynSeen.set(10)
            tcpEstablished.set(5)
            tcpProtectFailed.set(2)
            ipv6Dropped.set(900)
        }
        assertTrue(stats.diagnose().contains("protect() refused"))
    }

    @Test
    fun `syns with no establishment is called out as a hang`() {
        val stats = CaptureStats().apply {
            tcpSynSeen.set(24)
            tcpEstablished.set(0)
        }
        val verdict = stats.diagnose()
        assertTrue(verdict.contains("24 TCP connection attempt"))
        assertTrue(verdict.contains("none established"))
    }

    @Test
    fun `an ipv6 first network is identified when it dominates`() {
        val stats = CaptureStats().apply {
            tcpSynSeen.set(3)
            tcpEstablished.set(3)
            udpFlowsOpened.set(2)
            ipv6Dropped.set(400)
        }
        assertTrue(stats.diagnose().contains("IPv6-first"))
    }

    @Test
    fun `established connections with no return traffic is distinguished`() {
        val stats = CaptureStats().apply {
            tcpSynSeen.set(6)
            tcpEstablished.set(6)
            tcpBytesToServer.set(4096)
            tcpBytesToDevice.set(0)
        }
        assertTrue(stats.diagnose().contains("no bytes came back"))
    }

    @Test
    fun `a working relay reports healthy`() {
        val stats = CaptureStats().apply {
            tcpSynSeen.set(20)
            tcpEstablished.set(20)
            tcpBytesToServer.set(8192)
            tcpBytesToDevice.set(1_048_576)
            udpFlowsOpened.set(12)
            ipv6Dropped.set(4)
        }
        assertTrue(stats.diagnose().startsWith("Relay healthy"))
    }

    @Test
    fun `snapshot exposes every counter for the evidence log`() {
        val snapshot = CaptureStats().apply {
            tcpSynSeen.set(1)
            ipv6Dropped.set(2)
        }.snapshot()

        assertEquals(1L, snapshot["tcp_syn_seen"])
        assertEquals(2L, snapshot["ipv6_dropped"])
        assertTrue(snapshot.containsKey("tcp_protect_failed"))
        assertTrue(snapshot.containsKey("udp_bytes_to_device"))
    }
}
