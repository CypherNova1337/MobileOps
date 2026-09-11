package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.target.Target
import dev.cyphernova.mobileops.core.target.TargetSelection
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TargetSelectionTest {

    private val host = Target.Host("192.168.1.10", "printer.local")
    private val endpoint = Target.Endpoint("192.168.1.20", 8443)
    private val network = Target.Network("CorpWiFi", "AA:BB:CC:DD:EE:FF", 2437, "[WPA2-PSK-CCMP][ESS]", -55)

    @Test
    fun `hosts flattens hosts and endpoints but not networks`() {
        val selection = TargetSelection(listOf(host, endpoint, network))
        assertEquals(listOf("192.168.1.10", "192.168.1.20"), selection.hosts())
    }

    @Test
    fun `endpoints fills in the default port for bare hosts`() {
        val selection = TargetSelection(listOf(host, endpoint))
        assertEquals(
            listOf("192.168.1.10" to 443, "192.168.1.20" to 8443),
            selection.endpoints(defaultPort = 443),
        )
    }

    @Test
    fun `duplicate addresses collapse`() {
        val selection = TargetSelection(listOf(host, Target.Host("192.168.1.10")))
        assertEquals(1, selection.hosts().size)
    }

    @Test
    fun `networks are kept separate from hosts`() {
        val selection = TargetSelection(listOf(host, network))
        assertEquals(listOf(network), selection.networks())
        assertTrue(selection.hosts().none { it == network.bssid })
    }

    @Test
    fun `keys are stable and distinguish kinds`() {
        assertEquals("host:192.168.1.10", host.key)
        assertEquals("ep:192.168.1.20:8443", endpoint.key)
        assertEquals("net:AA:BB:CC:DD:EE:FF", network.key)
    }

    @Test
    fun `hidden network label falls back rather than showing empty`() {
        assertEquals("<hidden>", Target.Network("", "AA:BB:CC:DD:EE:00", 2437, "[ESS]", -70).label)
    }
}
