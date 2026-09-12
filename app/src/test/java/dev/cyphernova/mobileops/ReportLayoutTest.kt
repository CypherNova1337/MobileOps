package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.ReportLayout
import dev.cyphernova.mobileops.core.evidence.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A live run produced 177 findings, 144 of them observations, and the three that mattered were
 * somewhere in the middle. Making every failure explain itself fixed a real problem and created
 * another one — a report nobody can read is not better than one that hid things, the reader just
 * gives up at a different point.
 */
class ReportLayoutTest {

    private fun finding(
        severity: Severity = Severity.INFO,
        title: String = "",
        detail: String = "",
        subject: String = "",
        moduleId: String = "t0.net.smb",
        at: Long = 0,
        data: Map<String, String> = emptyMap(),
    ) = Finding(
        moduleId = moduleId,
        observedAtEpochMs = at,
        severity = severity,
        title = title,
        subject = subject,
        detail = detail,
        data = data,
    )

    @Test
    fun `critical and high lead, medium and low follow, info goes to the back`() {
        assertEquals(
            ReportLayout.Section.ACT_ON,
            ReportLayout.sectionFor(finding(Severity.CRITICAL, "Shares reachable")),
        )
        assertEquals(
            ReportLayout.Section.ACT_ON,
            ReportLayout.sectionFor(finding(Severity.HIGH, "SMB1 is enabled")),
        )
        assertEquals(
            ReportLayout.Section.FINDING,
            ReportLayout.sectionFor(finding(Severity.MEDIUM, "Self-signed certificate")),
        )
        assertEquals(
            ReportLayout.Section.FINDING,
            ReportLayout.sectionFor(finding(Severity.LOW, "Missing security headers")),
        )
    }

    /** The two kinds of INFO are not the same thing and do not belong in the same list. */
    @Test
    fun `what is there and what did not answer are separated`() {
        assertEquals(
            ReportLayout.Section.OBSERVATION,
            ReportLayout.sectionFor(finding(title = "UPnP: ReadyDLNA/1.3.0")),
        )
        listOf(
            "IPP did not answer on 192.168.61.1",
            "No HTTP reply from http://192.168.61.4:80",
            "Null session could not list shares on 192.168.61.1",
            "Path probing skipped on https://192.168.61.1:443",
            "Answers every path identically",
            "Blocked on this device: Evil twin / karma",
        ).forEach {
            assertEquals(it, ReportLayout.Section.DIAGNOSTIC, ReportLayout.sectionFor(finding(title = it)))
        }
    }

    @Test
    fun `the headline is the first sentence, which is where findings say what happened`() {
        val detail = "The session attached to R_Drive. That is not an inference from a comment."
        assertEquals(
            "The session attached to R_Drive.",
            ReportLayout.headline(finding(detail = detail)),
        )
    }

    /** A version, an address and a dialect all carry dots that end nothing. */
    @Test
    fun `a full stop inside a number does not end the headline`() {
        assertEquals(
            "The server negotiated NT LM 0.12.",
            ReportLayout.headline(
                finding(detail = "The server negotiated NT LM 0.12. SMB1 is the protocol WannaCry spread over."),
            ),
        )
        assertEquals(
            "Dialect 3.1.1 on 192.168.61.1.",
            ReportLayout.headline(finding(detail = "Dialect 3.1.1 on 192.168.61.1. Signing is not required.")),
        )
    }

    @Test
    fun `a detail with no sentence break is truncated rather than printed whole`() {
        val headline = ReportLayout.headline(finding(detail = "x".repeat(400)))
        assertTrue(headline.length <= 200)
    }

    // ---- Repeats ---------------------------------------------------------------------------

    @Test
    fun `re-running a module does not double the report`() {
        val once = finding(Severity.HIGH, "SMB1 is enabled", detail = "same", at = 100)
        val again = once.copy(observedAtEpochMs = 200)
        val collapsed = ReportLayout.collapse(listOf(once, again))
        assertEquals(1, collapsed.size)
        assertEquals(2, collapsed.single().times)
        assertEquals(100, collapsed.single().firstSeenEpochMs)
        assertEquals(200, collapsed.single().finding.observedAtEpochMs)
    }

    /** Same title and subject, different detail, is two findings — merging them drops one. */
    @Test
    fun `findings that say different things are not merged`() {
        val collapsed = ReportLayout.collapse(
            listOf(
                finding(Severity.HIGH, "Missing security headers", detail = "Absent: HSTS"),
                finding(Severity.HIGH, "Missing security headers", detail = "Absent: CSP"),
            ),
        )
        assertEquals(2, collapsed.size)
    }

    @Test
    fun `the most severe comes first`() {
        val collapsed = ReportLayout.collapse(
            listOf(
                finding(Severity.LOW, "low"),
                finding(Severity.CRITICAL, "critical"),
                finding(Severity.MEDIUM, "medium"),
            ),
        )
        assertEquals(listOf("critical", "medium", "low"), collapsed.map { it.finding.title })
    }

    // ---- The inventory ----------------------------------------------------------------------

    @Test
    fun `hosts are listed once, in address order, with what they are and what they run`() {
        val findings = listOf(
            finding(
                title = "Network infrastructure",
                data = mapOf(
                    "host" to "192.168.61.1",
                    "category" to "NETWORK_DEVICE",
                    "confidence" to "CONFIRMED",
                    "open_ports" to "443, 80, 53",
                ),
            ),
            finding(
                severity = Severity.CRITICAL,
                title = "Shares reachable",
                data = mapOf("host" to "192.168.61.1"),
            ),
            finding(
                title = "Printer",
                data = mapOf("host" to "192.168.61.6", "category" to "PRINTER", "open_ports" to "9100"),
            ),
        )
        val hosts = ReportLayout.hosts(findings)
        assertEquals(listOf("192.168.61.1", "192.168.61.6"), hosts.map { it.address })

        val gateway = hosts.first()
        assertTrue(gateway.description.contains("Network device"))
        assertTrue(gateway.description.contains("confirmed"))
        // Numeric order, not lexical: 53 before 80 before 443.
        assertEquals("53, 80, 443", gateway.openPorts)
        // Observations are not findings; only the critical counts.
        assertEquals(1, gateway.findingCount)
    }

    @Test
    fun `an address ordering is numeric so 2 sorts before 10`() {
        val findings = listOf("192.168.61.10", "192.168.61.2", "192.168.61.1").map {
            finding(data = mapOf("host" to it))
        }
        assertEquals(
            listOf("192.168.61.1", "192.168.61.2", "192.168.61.10"),
            ReportLayout.hosts(findings).map { it.address },
        )
    }

    @Test
    fun `a host with nothing wrong still appears, with no findings against it`() {
        val hosts = ReportLayout.hosts(listOf(finding(data = mapOf("host" to "192.168.61.9"))))
        assertEquals(1, hosts.size)
        assertEquals(0, hosts.single().findingCount)
        assertEquals("unidentified", hosts.single().description)
    }

    @Test
    fun `things that are not addresses never reach the host table`() {
        val findings = listOf(
            finding(data = mapOf("host" to "not.an.address.at.all")),
            finding(data = mapOf("host" to "999.1.1.1")),
            finding(data = mapOf("host" to "")),
        )
        assertTrue(ReportLayout.hosts(findings).isEmpty())
    }
}
