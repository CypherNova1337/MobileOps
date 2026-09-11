package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.iot.DeviceEvidence
import dev.cyphernova.mobileops.core.iot.DeviceFingerprint
import dev.cyphernova.mobileops.core.iot.DeviceFingerprint.Category
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceEvidenceTest {

    private fun finding(
        moduleId: String = "t0.net.services",
        subject: String = "",
        data: Map<String, String> = emptyMap(),
    ) = Finding(
        moduleId = moduleId,
        observedAtEpochMs = 0,
        severity = Severity.INFO,
        title = "",
        subject = subject,
        detail = "",
        data = data,
    )

    @Test
    fun `ports and banners are pooled from every finding about the host`() {
        val findings = listOf(
            finding(subject = "192.168.61.6", data = mapOf("open_ports" to "21, 80, 443")),
            finding(subject = "192.168.61.6:9100", data = mapOf("port" to "9100")),
            finding(
                subject = "192.168.61.6",
                data = mapOf("banners" to "21=220 Lexmark MS312dn FTP Server ready."),
            ),
        )
        val evidence = DeviceEvidence.forHost(findings, "192.168.61.6")
        assertEquals(setOf(21, 80, 443, 9100), evidence.openPorts)
        assertTrue(evidence.banners.getValue(21).contains("Lexmark"))
    }

    @Test
    fun `findings about other hosts are not pooled in`() {
        val findings = listOf(
            finding(subject = "192.168.61.6", data = mapOf("open_ports" to "21")),
            finding(subject = "192.168.61.9", data = mapOf("open_ports" to "445")),
        )
        assertEquals(setOf(21), DeviceEvidence.forHost(findings, "192.168.61.6").openPorts)
    }

    @Test
    fun `a host named in a data field rather than the subject is still matched`() {
        val findings = listOf(
            finding(subject = "192.168.61.0/24", data = mapOf("addresses" to "192.168.61.6,192.168.61.9")),
            finding(subject = "", data = mapOf("host" to "192.168.61.6", "hostname" to "PRINTER")),
        )
        assertTrue(DeviceEvidence.forHost(findings, "192.168.61.6").names.contains("PRINTER"))
    }

    /**
     * Taken from a live run. The gateway was reported as a workstation because nothing in
     * 53/80/139/443/445 says router — the fact that it routes for the segment lived in a
     * different module's finding entirely.
     */
    @Test
    fun `the gateway is recognised as infrastructure whatever its ports look like`() {
        val findings = listOf(
            finding(subject = "192.168.61.1", data = mapOf("open_ports" to "53, 80, 139, 443, 445")),
        )
        val evidence = DeviceEvidence.forHost(findings, "192.168.61.1", gateway = "192.168.61.1")
        assertEquals(Category.NETWORK_DEVICE, DeviceFingerprint.classify(evidence).category)
    }

    @Test
    fun `a host that is not the gateway is not promoted to infrastructure`() {
        val findings = listOf(
            finding(subject = "192.168.61.9", data = mapOf("open_ports" to "53, 80, 139, 443, 445")),
        )
        val evidence = DeviceEvidence.forHost(findings, "192.168.61.9", gateway = "192.168.61.1")
        assertEquals(Category.ENDPOINT, DeviceFingerprint.classify(evidence).category)
    }

    /**
     * Also from the live run: a Vizio television reported as a workstation, because the module
     * that saw `_viziocast._tcp` was not the module doing the classifying.
     */
    @Test
    fun `mdns service types reach the classifier`() {
        val findings = listOf(
            finding(subject = "192.168.61.7", data = mapOf("open_ports" to "8443")),
            finding(
                subject = "192.168.61.7",
                data = mapOf("services" to "_airplay._tcp.local, _hap._tcp.local, _viziocast._tcp.local"),
            ),
        )
        val evidence = DeviceEvidence.forHost(findings, "192.168.61.7")
        assertEquals(Category.MEDIA, DeviceFingerprint.classify(evidence).category)
    }

    @Test
    fun `a upnp server string is enough to name a router`() {
        val findings = listOf(
            finding(
                subject = "192.168.61.1",
                data = mapOf("server" to "3.13.0-115-generic DLNADOC/1.50 UPnP/1.0 ReadyDLNA/1.3.0"),
            ),
        )
        val evidence = DeviceEvidence.forHost(findings, "192.168.61.1")
        assertEquals(Category.NETWORK_DEVICE, DeviceFingerprint.classify(evidence).category)
    }

    /** Equipment still wins: a protocol answering is a fact, pooled names are inference. */
    @Test
    fun `a pooled name does not override a protocol port`() {
        val findings = listOf(
            finding(subject = "10.0.0.5", data = mapOf("open_ports" to "502", "hostname" to "office-tv")),
        )
        val evidence = DeviceEvidence.forHost(findings, "10.0.0.5")
        assertEquals(Category.INDUSTRIAL_CONTROL, DeviceFingerprint.classify(evidence).category)
    }

    /**
     * Routing for the segment is read off the interface, not guessed at from a product name, so
     * it should not be reported at the same confidence as a name that merely looked router-ish.
     */
    @Test
    fun `the gateway is confirmed infrastructure rather than inferred`() {
        val findings = listOf(
            finding(subject = "192.168.61.1", data = mapOf("open_ports" to "53, 80, 443")),
        )
        val evidence = DeviceEvidence.forHost(findings, "192.168.61.1", gateway = "192.168.61.1")
        val verdict = DeviceFingerprint.classify(evidence)
        assertEquals(Category.NETWORK_DEVICE, verdict.category)
        assertEquals(DeviceFingerprint.Confidence.CONFIRMED, verdict.confidence)
        assertTrue(verdict.basis.contains("routes for this segment"))
    }

    /** A gateway that also runs equipment says so, rather than hiding what else answered. */
    @Test
    fun `a gateway running another service still names that service`() {
        val findings = listOf(
            finding(subject = "192.168.61.1", data = mapOf("open_ports" to "80, 9100")),
        )
        val evidence = DeviceEvidence.forHost(findings, "192.168.61.1", gateway = "192.168.61.1")
        val verdict = DeviceFingerprint.classify(evidence)
        assertEquals(Category.NETWORK_DEVICE, verdict.category)
        assertTrue(verdict.significance.contains("printer", ignoreCase = true))
    }

    @Test
    fun `an empty log yields empty evidence rather than throwing`() {
        val evidence = DeviceEvidence.forHost(emptyList(), "192.168.61.6")
        assertTrue(evidence.openPorts.isEmpty())
        assertTrue(evidence.names.isEmpty())
        assertEquals(Category.UNKNOWN, DeviceFingerprint.classify(evidence).category)
    }
}
