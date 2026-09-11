package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.segment.SegmentProbe
import dev.cyphernova.mobileops.core.segment.SegmentProbe.ResolverPosture
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SegmentProbeTest {

    @Test
    fun `the rfc1918 ranges are recognised and their neighbours are not`() {
        listOf("10.0.0.1", "10.255.255.254", "172.16.0.1", "172.31.255.1", "192.168.61.1")
            .forEach { assertTrue(it, SegmentProbe.isPrivate(it)) }
        // 172.15 and 172.32 sit either side of the block and are public.
        listOf("8.8.8.8", "172.15.0.1", "172.32.0.1", "193.168.1.1", "11.0.0.1")
            .forEach { assertFalse(it, SegmentProbe.isPrivate(it)) }
    }

    @Test
    fun `link-local is told apart from a real lease`() {
        assertTrue(SegmentProbe.isLinkLocal("169.254.1.1"))
        assertFalse(SegmentProbe.isLinkLocal("192.168.1.1"))
    }

    /** Reaching your own subnet proves nothing about segmentation, so it is never probed. */
    @Test
    fun `candidates never include the caller's own subnet`() {
        val candidates = SegmentProbe.candidatesFor("192.168.61.0/24")
        assertTrue(candidates.isNotEmpty())
        assertFalse(candidates.any { it.address.startsWith("192.168.61.") })
    }

    @Test
    fun `candidates reach into neighbouring segments and other address plans`() {
        val addresses = SegmentProbe.candidatesFor("192.168.61.0/24").map { it.address }
        // One step either side catches the common "guest is next door" layout.
        assertTrue(addresses.contains("192.168.60.1"))
        assertTrue(addresses.contains("192.168.62.1"))
        // And the ranges a larger site carves its segments out of.
        assertTrue(addresses.contains("10.0.0.1"))
        assertTrue(addresses.contains("172.16.0.1"))
        assertTrue(addresses.contains("192.168.1.1"))
    }

    @Test
    fun `candidates are deduplicated and each says what reaching it would prove`() {
        val candidates = SegmentProbe.candidatesFor("192.168.1.0/24")
        assertEquals(candidates.map { it.address }.distinct().size, candidates.size)
        assertTrue(candidates.all { it.rationale.isNotBlank() })
        // Starting from 192.168.1, that subnet itself must be excluded even though it is a
        // conventional one.
        assertFalse(candidates.any { it.address == "192.168.1.1" })
    }

    @Test
    fun `a caller in 10-space still gets the other plans probed`() {
        val addresses = SegmentProbe.candidatesFor("10.1.1.0/24").map { it.address }
        assertTrue(addresses.contains("172.16.0.1"))
        assertTrue(addresses.contains("10.0.0.1"))
        assertFalse(addresses.contains("10.1.1.1"))
    }

    @Test
    fun `reverse names are built in the order dns expects`() {
        assertEquals("1.61.168.192.in-addr.arpa", SegmentProbe.reverseName("192.168.61.1"))
        assertNull(SegmentProbe.reverseName("192.168.61"))
        assertNull(SegmentProbe.reverseName("192.168.61.999"))
        assertNull(SegmentProbe.reverseName("not-an-address"))
    }

    @Test
    fun `directory records name the controllers a domain would publish`() {
        val records = SegmentProbe.directoryRecordsFor("corp.example.com").map { it.first }
        assertTrue(records.contains("_ldap._tcp.dc._msdcs.corp.example.com"))
        assertTrue(records.contains("_kerberos._tcp.corp.example.com"))
        assertTrue(records.contains("_gc._tcp.corp.example.com"))
        assertTrue(SegmentProbe.directoryRecordsFor("  ").isEmpty())
    }

    @Test
    fun `a trailing dot or capitals in the domain do not change the records`() {
        assertEquals(
            SegmentProbe.directoryRecordsFor("corp.example.com"),
            SegmentProbe.directoryRecordsFor("CORP.Example.COM."),
        )
    }

    /** An internal resolver on a visitor segment is a leak; a public one is the right answer. */
    @Test
    fun `resolver posture separates internal from public`() {
        assertEquals(
            ResolverPosture.INTERNAL,
            SegmentProbe.resolverPosture(listOf("10.0.0.53"), "192.168.1.1"),
        )
        assertEquals(
            ResolverPosture.PUBLIC,
            SegmentProbe.resolverPosture(listOf("8.8.8.8", "1.1.1.1"), "192.168.1.1"),
        )
        assertEquals(
            ResolverPosture.SELF,
            SegmentProbe.resolverPosture(listOf("192.168.1.1"), "192.168.1.1"),
        )
        assertEquals(ResolverPosture.NONE, SegmentProbe.resolverPosture(emptyList(), null))
    }

    @Test
    fun `peers cover the subnet without the network or broadcast address`() {
        val peers = SegmentProbe.peersOf("192.168.61.0/24", limit = 300)
        assertEquals(254, peers.size)
        assertEquals("192.168.61.1", peers.first())
        assertEquals("192.168.61.254", peers.last())
        assertFalse(peers.contains("192.168.61.0"))
        assertFalse(peers.contains("192.168.61.255"))
    }

    @Test
    fun `the peer sweep stays bounded and refuses a subnet too large to walk`() {
        assertEquals(64, SegmentProbe.peersOf("10.0.0.0/16", limit = 64).size)
        // A /21 or wider is millions of addresses; the module does not attempt it.
        assertTrue(SegmentProbe.peersOf("10.0.0.0/8").isEmpty())
    }

    @Test
    fun `a smaller prefix yields only the addresses it actually contains`() {
        val peers = SegmentProbe.peersOf("192.168.61.0/30")
        assertEquals(listOf("192.168.61.1", "192.168.61.2"), peers)
    }
}
