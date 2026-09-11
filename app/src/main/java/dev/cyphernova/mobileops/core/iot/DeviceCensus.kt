package dev.cyphernova.mobileops.core.iot

import dev.cyphernova.mobileops.core.evidence.Finding

/**
 * Re-decides what each device is, once the run is over.
 *
 * A module classifies with whatever the log held at the moment it ran, and that is a race it
 * loses. In a live run the port scan filed its verdict on one host at 17:40:52 and service
 * discovery announced `_viziocast._tcp` for the same host at 17:40:53 — one second later. The
 * television was reported as a workstation, and pooling evidence did not help, because the
 * evidence that would have settled it did not exist yet.
 *
 * Ordering is not something an operator should have to get right. The report is rendered after
 * everything has run, so classification is redone here against the complete log: every port, every
 * banner, every advertised service, whenever each of them arrived.
 */
object DeviceCensus {

    /**
     * [findings] with every classification verdict recomputed against the whole log.
     *
     * Findings that are not classifications pass through untouched, and so does a verdict the
     * fuller evidence agrees with — rewriting one that did not change would only churn the report.
     */
    fun reclassified(findings: List<Finding>): List<Finding> {
        val gateway = gatewayIn(findings)
        return findings.map { finding ->
            val host = finding.data["host"]?.trim()?.takeIf { it.isNotBlank() }
                ?: return@map finding
            val recorded = finding.data["category"]?.takeIf { it.isNotBlank() }
                ?: return@map finding

            val verdict = DeviceFingerprint.classify(
                DeviceEvidence.forHost(findings, host, gateway),
            )
            if (verdict.category.name == recorded &&
                verdict.confidence.name == finding.data["confidence"]
            ) {
                return@map finding
            }

            finding.copy(
                title = "${verdict.category.label} — $host",
                detail = describe(verdict, changedFrom = recorded),
                data = finding.data + mapOf(
                    "category" to verdict.category.name,
                    "confidence" to verdict.confidence.name,
                    "fragility" to verdict.fragility.name,
                    // Kept so a reader can see the verdict moved and why, rather than wondering
                    // whether two modules disagreed.
                    "category_at_scan_time" to recorded,
                ),
            )
        }
    }

    private fun describe(verdict: DeviceFingerprint.Verdict, changedFrom: String): String =
        buildString {
            append("Identified as ${verdict.category.label} (${verdict.confidence.label}): ")
            append("${verdict.basis}. ")
            if (verdict.significance.isNotBlank()) append("${verdict.significance} ")
            if (changedFrom != verdict.category.name) {
                append(
                    "Recorded during the scan as ${labelOf(changedFrom)}; re-read here against " +
                        "everything the run found afterwards, which is what changed the answer.",
                )
            }
        }.trim()

    private fun labelOf(name: String): String =
        DeviceFingerprint.Category.entries.firstOrNull { it.name == name }?.label ?: name

    /** The gateway, from whichever module established it. */
    private fun gatewayIn(findings: List<Finding>): String? = findings
        .firstNotNullOfOrNull { it.data["gateway"]?.trim()?.takeIf { value -> value.isNotBlank() } }
}
