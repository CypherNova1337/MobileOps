package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.target.HostHarvest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class HostHarvestTest {

    private fun finding(
        moduleId: String = "t0.net.discovery",
        title: String = "something",
        subject: String = "",
        data: Map<String, String> = emptyMap(),
    ) = Finding(
        moduleId = moduleId,
        observedAtEpochMs = 0,
        severity = Severity.INFO,
        title = title,
        subject = subject,
        detail = "",
        data = data,
    )

    /**
     * The regression this exists for. The Targets tab used to match findings whose title began
     * "Live host", so rewriting that title to cut report noise silently emptied it and left every
     * host module with nothing to point at. Nothing here may depend on prose.
     */
    @Test
    fun `hosts come out of the census regardless of what it is titled`() {
        val census = finding(
            title = "11 live host(s) on 192.168.61.0/24",
            subject = "192.168.61.0/24",
            data = mapOf(
                "addresses" to "192.168.61.1, 192.168.61.6, 192.168.61.16",
                "live" to "3",
            ),
        )
        assertEquals(
            listOf("192.168.61.1", "192.168.61.6", "192.168.61.16"),
            HostHarvest.hostsIn(listOf(census)).map { it.address },
        )
    }

    @Test
    fun `every field modules use to report hosts is read`() {
        val findings = listOf(
            finding(data = mapOf("addresses" to "10.0.0.1,10.0.0.2")),
            finding(data = mapOf("peers" to "10.0.0.3")),
            finding(data = mapOf("host" to "10.0.0.4")),
            finding(data = mapOf("gateway" to "10.0.0.5")),
            finding(data = mapOf("reached" to "10.0.0.6")),
            finding(data = mapOf("hosts" to "10.0.0.7")),
        )
        assertEquals(
            (1..7).map { "10.0.0.$it" },
            HostHarvest.hostsIn(findings).map { it.address },
        )
    }

    /** A finding about a host names it in the subject, so that counts too. */
    @Test
    fun `an address in the subject is harvested`() {
        val service = finding(
            moduleId = "t0.net.services",
            title = "NetBIOS name: DRIVE",
            subject = "192.168.61.1",
            data = mapOf("hostname" to "DRIVE"),
        )
        assertEquals(listOf("192.168.61.1"), HostHarvest.hostsIn(listOf(service)).map { it.address })
    }

    /** The sweep finds an address and something else names it; the two only meet here. */
    @Test
    fun `names found by one module attach to addresses found by another`() {
        val findings = listOf(
            finding(data = mapOf("addresses" to "192.168.61.1,192.168.61.16")),
            finding(subject = "192.168.61.16", data = mapOf("hostname" to "ROBS")),
        )
        val hosts = HostHarvest.hostsIn(findings)
        assertEquals("ROBS", hosts.first { it.address == "192.168.61.16" }.hostname)
        assertNull(hosts.first { it.address == "192.168.61.1" }.hostname)
    }

    @Test
    fun `a host seen by several modules appears once`() {
        val findings = listOf(
            finding(data = mapOf("addresses" to "192.168.61.6")),
            finding(data = mapOf("host" to "192.168.61.6")),
            finding(subject = "192.168.61.6"),
        )
        assertEquals(1, HostHarvest.hostsIn(findings).size)
    }

    /** Sorting as strings would put .10 before .2, which reads as broken in a list. */
    @Test
    fun `addresses come back in numeric order`() {
        val census = finding(
            data = mapOf("addresses" to "192.168.61.100,192.168.61.2,192.168.61.19,192.168.61.1"),
        )
        assertEquals(
            listOf("192.168.61.1", "192.168.61.2", "192.168.61.19", "192.168.61.100"),
            HostHarvest.hostsIn(listOf(census)).map { it.address },
        )
    }

    @Test
    fun `subjects that are not addresses are ignored`() {
        val findings = listOf(
            // A CIDR, a BSSID and an SSID all turn up as subjects.
            finding(subject = "192.168.61.0/24"),
            finding(subject = "80:cc:9c:13:18:c4"),
            finding(subject = "VoidSec"),
            finding(subject = "RF environment"),
        )
        assertTrue(HostHarvest.hostsIn(findings).isEmpty())
    }

    @Test
    fun `octet validation rejects what is not an address`() {
        listOf("192.168.61.1", "0.0.0.0", "255.255.255.255").forEach {
            assertTrue(it, HostHarvest.isIpv4(it))
        }
        listOf(
            "192.168.61", "192.168.61.256", "192.168.61.1.1", "192.168.61.",
            "1921.68.61.1", "a.b.c.d", "", "192.168.61.0/24",
        ).forEach { assertFalse(it, HostHarvest.isIpv4(it)) }
    }

    @Test
    fun `whitespace around a comma-separated list is tolerated`() {
        val census = finding(data = mapOf("addresses" to " 10.0.0.1 ,  10.0.0.2 "))
        assertEquals(
            listOf("10.0.0.1", "10.0.0.2"),
            HostHarvest.hostsIn(listOf(census)).map { it.address },
        )
    }

    @Test
    fun `an empty log yields nothing rather than throwing`() {
        assertTrue(HostHarvest.hostsIn(emptyList()).isEmpty())
        assertTrue(HostHarvest.addressesIn(finding()).isEmpty())
    }
}
