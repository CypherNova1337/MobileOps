package dev.cyphernova.mobileops.core.evidence

/**
 * How a report is arranged, kept apart from how it is rendered so the decisions can be tested.
 *
 * Making every failure explain itself fixed a real problem and created another one: a live run
 * produced 177 findings, 144 of them INFO, and the three that mattered were somewhere in the
 * middle of it. A report nobody can read is not a better report than one that hid things — the
 * reader simply gives up at a different point.
 *
 * Nothing is discarded here. The arrangement decides what is read first, what is read in full,
 * and what waits at the back until somebody wants it.
 */
object ReportLayout {

    /** Where a finding belongs in the report. */
    enum class Section {
        /** Critical and High: the reason the tool was run. */
        ACT_ON,

        /** Medium and Low: real, with full detail, after the urgent ones. */
        FINDING,

        /** INFO that records what is on the network. Compact, one line each. */
        OBSERVATION,

        /** INFO that records what did not answer. Compact, and last. */
        DIAGNOSTIC,
    }

    /**
     * Titles that mean "this did not work", rather than "this is what is there".
     *
     * They earn their place in the log — a silent failure cost this project several rounds of
     * guessing — but they are the answer to a question nobody has asked yet, so they go last.
     */
    private val DIAGNOSTIC_MARKERS = listOf(
        "did not answer",
        "no reply",
        "no http reply",
        "could not",
        "skipped",
        "not offered",
        "answers every path",
        "did not hand over",
        "no upnp description",
        "handshake failed",
        "blocked on this device",
        "one page served for several paths",
    )

    fun sectionFor(finding: Finding): Section = when {
        finding.severity.rank >= Severity.HIGH.rank -> Section.ACT_ON
        finding.severity != Severity.INFO -> Section.FINDING
        isDiagnostic(finding) -> Section.DIAGNOSTIC
        else -> Section.OBSERVATION
    }

    /**
     * Fields a module fills in only when it is explaining a failure.
     *
     * Structure first, wording second. Matching on the title alone missed "No HTTP reply from …"
     * because the marker read "no reply" — which is the same brittleness as every other
     * string-matching mistake in this codebase, and the reason a finding carries data at all.
     */
    private val DIAGNOSTIC_FIELDS = listOf("stopped_at", "attempted", "controls_attempted")

    fun isDiagnostic(finding: Finding): Boolean {
        if (DIAGNOSTIC_FIELDS.any { finding.data[it]?.isNotBlank() == true }) return true
        val title = finding.title.lowercase()
        return DIAGNOSTIC_MARKERS.any { title.contains(it) }
    }

    /**
     * One line summarising a finding, for the list a reader starts with.
     *
     * The first sentence of the detail, because findings here are written so the first sentence
     * says what happened and the rest says why it matters.
     */
    fun headline(finding: Finding): String {
        val text = finding.detail.replace('\n', ' ').trim()
        // A sentence ends at a full stop followed by a space, not at any full stop. Breaking on
        // the first one turned "negotiated NT LM 0.12" into "negotiated NT LM 0." — a version
        // number, an address and a dialect all carry dots that are not the end of anything.
        val end = text.indexOf(". ")
        val sentence = if (end > 0) text.take(end + 1) else text
        // The ellipsis counts toward the limit; a cap that its own marker overruns is not a cap.
        return if (sentence.length <= HEADLINE_CHARS) sentence
        else text.take(HEADLINE_CHARS - 1).trim() + "…"
    }

    private const val HEADLINE_CHARS = 200

    /**
     * Collapses repeats.
     *
     * Re-running a module re-files everything it saw, so a second pass doubles the report. Keyed
     * on the detail as well as the title: findings that share a title and subject but say
     * different things are different findings, and merging them drops one.
     */
    fun collapse(findings: List<Finding>): List<Occurrence> = findings
        .groupBy { listOf(it.moduleId, it.title, it.subject, it.detail) }
        .values
        .map { group ->
            Occurrence(
                finding = group.maxBy { it.observedAtEpochMs },
                times = group.size,
                firstSeenEpochMs = group.minOf { it.observedAtEpochMs },
            )
        }
        .sortedWith(
            compareByDescending<Occurrence> { it.finding.severity.rank }
                .thenBy { it.finding.observedAtEpochMs },
        )

    data class Occurrence(
        val finding: Finding,
        val times: Int,
        val firstSeenEpochMs: Long,
    )

    /** A host as the report should describe it: what it is, what it runs, what was found. */
    data class HostRow(
        val address: String,
        val description: String,
        val openPorts: String,
        val findingCount: Int,
    )

    /**
     * The inventory table.
     *
     * Built from the log rather than from a module, because what a host is and what was found on
     * it come from different places — and twenty separate INFO findings saying "5 open ports on
     * X" is the same information in the form nobody can read.
     */
    fun hosts(findings: List<Finding>): List<HostRow> {
        val addresses = findings
            .mapNotNull { it.data["host"]?.trim()?.takeIf(::looksLikeAddress) }
            .distinct()

        return addresses.map { address ->
            val mine = findings.filter { about(it, address) }
            HostRow(
                address = address,
                description = mine.firstNotNullOfOrNull { finding ->
                    finding.data["category"]?.let { category ->
                        val confidence = finding.data["confidence"]?.lowercase()
                        label(category) + (confidence?.let { " ($it)" } ?: "")
                    }
                } ?: "unidentified",
                openPorts = mine
                    .flatMap { it.data["open_ports"].orEmpty().split(',') }
                    .map { it.trim() }
                    .filter { it.isNotBlank() }
                    .distinct()
                    .sortedBy { it.toIntOrNull() ?: Int.MAX_VALUE }
                    .joinToString(", "),
                // Only findings that say something is wrong. Every host has observations.
                findingCount = mine.count { it.severity != Severity.INFO },
            )
        }.sortedBy { row -> row.address.split('.').mapNotNull { it.toIntOrNull() } .fold(0L) { acc, o -> acc * 256 + o } }
    }

    private fun about(finding: Finding, address: String): Boolean =
        finding.data["host"]?.trim() == address || finding.subject.trim() == address

    private fun label(category: String): String = category
        .lowercase()
        .replace('_', ' ')
        .replaceFirstChar { it.uppercase() }

    private fun looksLikeAddress(value: String): Boolean {
        val parts = value.split('.')
        return parts.size == 4 && parts.all { it.toIntOrNull() in 0..255 }
    }
}
