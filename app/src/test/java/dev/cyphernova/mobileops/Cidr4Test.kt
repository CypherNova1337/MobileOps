package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.net.Cidr4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class Cidr4Test {

    @Test
    fun `parses dotted quad`() {
        assertEquals(0xC0A80101L, Cidr4.parseAddress("192.168.1.1"))
        assertEquals(null, Cidr4.parseAddress("192.168.1"))
        assertEquals(null, Cidr4.parseAddress("192.168.1.256"))
    }

    @Test
    fun `contains respects prefix boundaries`() {
        assertTrue(Cidr4.contains("192.168.1.0/24", "192.168.1.42"))
        assertFalse(Cidr4.contains("192.168.1.0/24", "192.168.2.42"))
        assertTrue(Cidr4.contains("10.0.0.0/8", "10.255.255.254"))
        assertFalse(Cidr4.contains("10.0.0.0/8", "11.0.0.1"))
    }

    @Test
    fun `host enumeration excludes network and broadcast`() {
        assertEquals(
            listOf(
                "192.168.1.1", "192.168.1.2", "192.168.1.3",
                "192.168.1.4", "192.168.1.5", "192.168.1.6",
            ),
            Cidr4.hosts("192.168.1.0/29"),
        )
    }

    @Test
    fun `host enumeration is capped`() {
        assertEquals(50, Cidr4.hosts("10.0.0.0/16", limit = 50).size)
    }

    @Test
    fun `round trips through the integer form`() {
        assertEquals("172.16.31.9", Cidr4.toDotted(Cidr4.parseAddress("172.16.31.9")!!))
    }
}
