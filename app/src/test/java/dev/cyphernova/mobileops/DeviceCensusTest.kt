package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.iot.DeviceCensus
import dev.cyphernova.mobileops.core.iot.DeviceFingerprint.Category
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceCensusTest {

    private fun finding(
        moduleId: String = "t0.net.portscan",
        subject: String = "",
        title: String = "",
        detail: String = "",
        data: Map<String, String> = emptyMap(),
    ) = Finding(
        moduleId = moduleId,
        observedAtEpochMs = 0,
        severity = Severity.INFO,
        title = title,
        subject = subject,
        detail = detail,
        data = data,
    )

    private fun classification(host: String, ports: String, category: Category) = finding(
        subject = host,
        title = "${category.label} — $host",
        data = mapOf(
            "host" to host,
            "category" to category.name,
            "confidence" to "INFERRED",
            "fragility" to "ROBUST",
            "open_ports" to ports,
        ),
    )

    /**
     * Straight from a live run. The port scan filed its verdict on 192.168.61.7 at 17:40:52 and
     * service discovery announced `_viziocast._tcp` for the same host at 17:40:53 — one second
     * later, so pooling could not help. The television was reported as a workstation.
     */
    @Test
    fun `a verdict filed before the evidence arrived is corrected`() {
        val findings = listOf(
            classification("192.168.61.7", "8443", Category.ENDPOINT),
            finding(
                moduleId = "t0.net.services",
                subject = "192.168.61.7",
                data = mapOf("services" to "_airplay._tcp.local, _viziocast._tcp.local"),
            ),
        )
        val verdict = DeviceCensus.reclassified(findings).first()
        assertEquals(Category.MEDIA.name, verdict.data["category"])
        assertEquals(Category.ENDPOINT.name, verdict.data["category_at_scan_time"])
        assertTrue(verdict.title.contains("192.168.61.7"))
        assertTrue(verdict.detail.contains("re-read here"))
    }

    /** Order must stop mattering: the same log in either order gives the same answer. */
    @Test
    fun `the result does not depend on the order the modules ran in`() {
        val scan = classification("192.168.61.7", "8443", Category.ENDPOINT)
        val mdns = finding(
            moduleId = "t0.net.services",
            subject = "192.168.61.7",
            data = mapOf("services" to "_viziocast._tcp.local"),
        )
        val forwards = DeviceCensus.reclassified(listOf(scan, mdns)).first { it.data["category"] != null }
        val backwards = DeviceCensus.reclassified(listOf(mdns, scan)).first { it.data["category"] != null }
        assertEquals(forwards.data["category"], backwards.data["category"])
        assertEquals(Category.MEDIA.name, forwards.data["category"])
    }

    @Test
    fun `a verdict the fuller evidence agrees with is left exactly as it was`() {
        val findings = listOf(
            finding(
                subject = "192.168.61.6",
                title = "Printer / multifunction — 192.168.61.6",
                detail = "original text",
                data = mapOf(
                    "host" to "192.168.61.6",
                    "category" to Category.PRINTER.name,
                    "confidence" to "CONFIRMED",
                    "fragility" to "EMBEDDED",
                    "open_ports" to "631, 9100",
                    "banners" to "21=220 Lexmark MS312dn FTP Server ready.",
                ),
            ),
        )
        val after = DeviceCensus.reclassified(findings).first()
        assertEquals("original text", after.detail)
        assertFalse(after.data.containsKey("category_at_scan_time"))
    }

    @Test
    fun `the gateway is recognised wherever in the log it was established`() {
        val findings = listOf(
            classification("192.168.61.1", "53, 80, 139, 443, 445", Category.ENDPOINT),
            finding(
                moduleId = "t0.net.discovery",
                subject = "192.168.61.0/24",
                data = mapOf("gateway" to "192.168.61.1"),
            ),
        )
        val verdict = DeviceCensus.reclassified(findings).first()
        assertEquals(Category.NETWORK_DEVICE.name, verdict.data["category"])
        assertEquals("CONFIRMED", verdict.data["confidence"])
    }

    @Test
    fun `findings that are not classifications pass through untouched`() {
        val findings = listOf(
            finding(subject = "192.168.61.6:21", title = "ftp", data = mapOf("port" to "21")),
            finding(moduleId = "t0.net.smb", subject = "192.168.61.1", title = "SMB1 is enabled"),
        )
        assertEquals(findings, DeviceCensus.reclassified(findings))
    }

    @Test
    fun `an empty log is handled without throwing`() {
        assertTrue(DeviceCensus.reclassified(emptyList()).isEmpty())
    }
}
