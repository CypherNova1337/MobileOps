package dev.cyphernova.mobileops.core.evidence

import dev.cyphernova.mobileops.core.iot.DeviceCensus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Append-only evidence log, one JSON object per line so a partially written file still parses
 * up to the last complete record — findings survive the app being killed mid-sweep.
 */
class EvidenceStore(private val directory: File) {

    private val json = Json { ignoreUnknownKeys = true }
    private val writeLock = Mutex()
    private val _findings = MutableStateFlow<List<Finding>>(emptyList())
    val findings: StateFlow<List<Finding>> = _findings.asStateFlow()

    private val logFile: File get() = File(directory, LOG_NAME)

    suspend fun load() = withContext(Dispatchers.IO) {
        if (!logFile.exists()) return@withContext
        val loaded = logFile.readLines()
            .filter { it.isNotBlank() }
            .mapNotNull { line -> runCatching { json.decodeFromString<Finding>(line) }.getOrNull() }
        _findings.value = loaded
    }

    suspend fun record(finding: Finding) = withContext(Dispatchers.IO) {
        writeLock.withLock {
            directory.mkdirs()
            logFile.appendText(json.encodeToString(Finding.serializer(), finding) + "\n")
            _findings.value = _findings.value + finding
        }
    }

    suspend fun clear() = withContext(Dispatchers.IO) {
        writeLock.withLock {
            logFile.delete()
            _findings.value = emptyList()
        }
    }

    /**
     * Renders the log as a Markdown report.
     *
     * Two things are decided here rather than by the modules. Device verdicts are recomputed
     * against the complete log, because the evidence that settles what a device is often arrives
     * from another module seconds after the one that classified it. And the arrangement is
     * decided here, because only the finished log knows what is worth reading first — a run that
     * produced 177 findings, 144 of them observations, buried the three that mattered.
     *
     * Nothing is dropped. Urgent findings lead, real findings follow in full, and the record of
     * what is on the network and what failed to answer waits at the back in a form that can be
     * skimmed.
     */
    fun renderReport(findings: List<Finding> = _findings.value): String =
        buildString {
            @Suppress("NAME_SHADOWING") val findings = DeviceCensus.reclassified(findings)
            appendLine("# MobileOps report")
            appendLine()
            appendLine("Generated ${formatTime(System.currentTimeMillis())}")
            appendLine()

            if (findings.isEmpty()) {
                appendLine("No findings recorded.")
                return@buildString
            }

            val collapsed = ReportLayout.collapse(findings)
            val sections = collapsed.groupBy { ReportLayout.sectionFor(it.finding) }
            val actOn = sections[ReportLayout.Section.ACT_ON].orEmpty()
            val other = sections[ReportLayout.Section.FINDING].orEmpty()
            val observations = sections[ReportLayout.Section.OBSERVATION].orEmpty()
            val diagnostics = sections[ReportLayout.Section.DIAGNOSTIC].orEmpty()

            // ---- What to do about it ------------------------------------------------------
            appendLine("## Act on these")
            appendLine()
            if (actOn.isEmpty()) {
                appendLine(
                    "Nothing critical or high. That is the absence of evidence, not evidence of " +
                        "absence: see what did not answer, at the end.",
                )
            } else {
                actOn.forEachIndexed { index, occurrence ->
                    val finding = occurrence.finding
                    appendLine("${index + 1}. **${finding.title}** — ${finding.severity.label}")
                    appendLine("   ${ReportLayout.headline(finding)}")
                }
            }
            appendLine()

            appendLine(
                "${actOn.size} to act on · ${other.size} further finding(s) · " +
                    "${observations.size} observation(s) · ${diagnostics.size} unanswered",
            )
            appendLine()

            // ---- What is on the network ---------------------------------------------------
            val hosts = ReportLayout.hosts(findings)
            if (hosts.isNotEmpty()) {
                appendLine("## Hosts")
                appendLine()
                appendLine("| Address | What it is | Open ports | Findings |")
                appendLine("| --- | --- | --- | --- |")
                hosts.forEach { host ->
                    appendLine(
                        "| ${host.address} | ${host.description} | " +
                            "${host.openPorts.ifBlank { "—" }} | ${host.findingCount} |",
                    )
                }
                appendLine()
            }

            // ---- The findings, in full ----------------------------------------------------
            if (actOn.isNotEmpty() || other.isNotEmpty()) {
                appendLine("## Findings")
                appendLine()
                (actOn + other)
                    .groupBy { it.finding.severity }
                    .toSortedMap(compareByDescending { it.rank })
                    .forEach { (severity, group) ->
                        appendLine("### ${severity.label} (${group.size})")
                        appendLine()
                        group.forEach { appendDetail(it) }
                    }
            }

            // ---- The record ----------------------------------------------------------------
            if (observations.isNotEmpty()) {
                appendLine("## Observations (${observations.size})")
                appendLine()
                appendLine("What is on the network. No action implied.")
                appendLine()
                observations
                    .sortedBy { it.finding.moduleId }
                    .groupBy { it.finding.moduleId }
                    .forEach { (moduleId, group) ->
                        appendLine("**`$moduleId`**")
                        appendLine()
                        group.forEach { appendCompact(it) }
                        appendLine()
                    }
            }

            if (diagnostics.isNotEmpty()) {
                appendLine("## Did not answer (${diagnostics.size})")
                appendLine()
                appendLine(
                    "Asked and got nothing usable. Kept because a failure with no reason " +
                        "recorded is indistinguishable from a module that never ran.",
                )
                appendLine()
                diagnostics
                    .sortedBy { it.finding.moduleId }
                    .groupBy { it.finding.moduleId }
                    .forEach { (moduleId, group) ->
                        appendLine("**`$moduleId`**")
                        appendLine()
                        group.forEach { appendCompact(it) }
                        appendLine()
                    }
            }
        }

    /** A finding in full: everything it says, plus the evidence behind it. */
    private fun StringBuilder.appendDetail(occurrence: ReportLayout.Occurrence) {
        val finding = occurrence.finding
        appendLine("#### ${finding.title}")
        appendLine()
        appendLine("`${finding.moduleId}` · ${finding.subject} · ${formatTime(finding.observedAtEpochMs)}")
        if (occurrence.times > 1) {
            appendLine()
            appendLine("Seen ${occurrence.times} times, first at ${formatTime(occurrence.firstSeenEpochMs)}.")
        }
        appendLine()
        appendLine(finding.detail)
        if (finding.data.isNotEmpty()) {
            appendLine()
            finding.data.forEach { (key, value) -> appendLine("  - `$key`: $value") }
        }
        appendLine()
    }

    /** One line. The detail is in the log; this is the index to it. */
    private fun StringBuilder.appendCompact(occurrence: ReportLayout.Occurrence) {
        val finding = occurrence.finding
        // The subject is only worth repeating when the title has not already named it.
        val subject = finding.subject
            .takeIf { it.isNotBlank() && !finding.title.contains(it) }
            ?.let { " — $it" }
            .orEmpty()
        appendLine("- ${finding.title}$subject")
    }

    private fun formatTime(epochMs: Long): String = ISO.format(Date(epochMs))

    private companion object {
        const val LOG_NAME = "evidence.jsonl"
        val ISO = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
    }
}
