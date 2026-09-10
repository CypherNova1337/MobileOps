package dev.cyphernova.mobileops.core.evidence

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

    /** Renders the log as a Markdown report ready to drop into a write-up. */
    fun renderReport(findings: List<Finding> = _findings.value): String =
        buildString {
            appendLine("# MobileOps report")
            appendLine()
            appendLine("Generated ${formatTime(System.currentTimeMillis())}")
            appendLine()

            val bySeverity = findings.groupingBy { it.severity }.eachCount()
            if (bySeverity.isNotEmpty()) {
                appendLine("| Severity | Count |")
                appendLine("| --- | --- |")
                Severity.entries.sortedByDescending { it.rank }.forEach { severity ->
                    bySeverity[severity]?.let { appendLine("| ${severity.label} | $it |") }
                }
                appendLine()
            }

            appendLine("## Findings (${findings.size})")
            appendLine()
            if (findings.isEmpty()) {
                appendLine("No findings recorded.")
                return@buildString
            }
            findings.sortedWith(
                compareByDescending<Finding> { it.severity.rank }.thenBy { it.observedAtEpochMs },
            ).forEach { finding ->
                appendLine("### [${finding.severity.label}] ${finding.title}")
                appendLine()
                appendLine("- **Subject:** ${finding.subject}")
                appendLine("- **Module:** `${finding.moduleId}`")
                appendLine("- **Observed:** ${formatTime(finding.observedAtEpochMs)}")
                appendLine()
                appendLine(finding.detail)
                if (finding.data.isNotEmpty()) {
                    appendLine()
                    finding.data.forEach { (key, value) -> appendLine("  - `$key`: $value") }
                }
                appendLine()
            }
        }

    private fun formatTime(epochMs: Long): String = ISO.format(Date(epochMs))

    private companion object {
        const val LOG_NAME = "evidence.jsonl"
        val ISO = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
    }
}
