package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.exploit.UpnpLocations
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UpnpLocationsTest {

    private fun finding(
        subject: String = "",
        data: Map<String, String> = emptyMap(),
    ) = Finding(
        moduleId = "t0.net.services",
        observedAtEpochMs = 0,
        severity = Severity.INFO,
        title = "",
        subject = subject,
        detail = "",
        data = data,
    )

    private val guesses = listOf("http://192.168.61.1:49152/wps_device.xml")

    /**
     * Taken from a live run. Service discovery reported the description URL; the registrar module
     * guessed at ports instead of reading it, failed, and reported "no UPnP device description
     * found" about a host whose description was in the log.
     */
    @Test
    fun `an advertised location is tried before any guess`() {
        val findings = listOf(
            finding(
                subject = "192.168.61.1",
                data = mapOf(
                    "location" to "http://192.168.61.1:1681/rootDesc.xml",
                    "service_types" to "urn:schemas-wifialliance-org:service:WFAWLANConfig:1",
                ),
            ),
        )
        val candidates = UpnpLocations.candidatesFor(findings, "192.168.61.1", guesses)
        assertEquals("http://192.168.61.1:1681/rootDesc.xml", candidates.first())
        assertTrue(candidates.containsAll(guesses))
    }

    /** A router answers from several daemons on one address; only one of them is the registrar. */
    @Test
    fun `the location that answered for the wps service comes first`() {
        val findings = listOf(
            finding(
                subject = "192.168.61.1",
                data = mapOf(
                    "locations" to "http://192.168.61.1:8200/rootDesc.xml, " +
                        "http://192.168.61.1:49152/wps_device.xml",
                    "wps_location" to "http://192.168.61.1:49152/wps_device.xml",
                ),
            ),
        )
        assertEquals(
            "http://192.168.61.1:49152/wps_device.xml",
            UpnpLocations.advertisedFor(findings, "192.168.61.1").first(),
        )
    }

    @Test
    fun `a location pointing at another address is not probed`() {
        val findings = listOf(
            finding(
                subject = "192.168.61.1",
                data = mapOf("location" to "http://192.168.61.9:1400/xml/device_description.xml"),
            ),
        )
        assertTrue(UpnpLocations.advertisedFor(findings, "192.168.61.1").isEmpty())
    }

    @Test
    fun `findings about other hosts contribute nothing`() {
        val findings = listOf(
            finding(
                subject = "192.168.61.7",
                data = mapOf("location" to "http://192.168.61.7:1677/rootDesc.xml"),
            ),
        )
        assertEquals(guesses, UpnpLocations.candidatesFor(findings, "192.168.61.1", guesses))
    }

    @Test
    fun `a host named in a data field is matched as well as one in the subject`() {
        val findings = listOf(
            finding(
                data = mapOf(
                    "host" to "192.168.61.1",
                    "location" to "http://192.168.61.1:5000/rootDesc.xml",
                ),
            ),
        )
        assertEquals(
            listOf("http://192.168.61.1:5000/rootDesc.xml"),
            UpnpLocations.advertisedFor(findings, "192.168.61.1"),
        )
    }

    @Test
    fun `a non-http location is ignored rather than probed`() {
        val findings = listOf(
            finding(subject = "192.168.61.1", data = mapOf("location" to "192.168.61.1:49152")),
        )
        assertTrue(UpnpLocations.advertisedFor(findings, "192.168.61.1").isEmpty())
    }

    @Test
    fun `the same location advertised by several replies is probed once`() {
        val url = "http://192.168.61.1:49152/wps_device.xml"
        val findings = listOf(
            finding(subject = "192.168.61.1", data = mapOf("location" to url)),
            finding(subject = "192.168.61.1", data = mapOf("location" to url)),
        )
        val candidates = UpnpLocations.candidatesFor(findings, "192.168.61.1", guesses)
        assertEquals(1, candidates.count { it == url })
    }

    @Test
    fun `a url naming wps outranks one that does not even without a service type`() {
        val findings = listOf(
            finding(
                subject = "192.168.61.1",
                data = mapOf(
                    "locations" to "http://192.168.61.1:8200/rootDesc.xml, " +
                        "http://192.168.61.1:49152/wps_device.xml",
                ),
            ),
        )
        assertEquals(
            "http://192.168.61.1:49152/wps_device.xml",
            UpnpLocations.advertisedFor(findings, "192.168.61.1").first(),
        )
    }

    @Test
    fun `a bracketed ipv6 location is matched against its own address`() {
        val findings = listOf(
            finding(
                subject = "fe80::1",
                data = mapOf("location" to "http://[fe80::1]:49152/wps_device.xml"),
            ),
        )
        assertFalse(UpnpLocations.advertisedFor(findings, "fe80::1").isEmpty())
    }

    @Test
    fun `an empty log leaves only the guesses`() {
        assertEquals(guesses, UpnpLocations.candidatesFor(emptyList(), "192.168.61.1", guesses))
    }
}
