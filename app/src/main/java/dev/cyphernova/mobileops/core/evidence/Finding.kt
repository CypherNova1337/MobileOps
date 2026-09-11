package dev.cyphernova.mobileops.core.evidence

import kotlinx.serialization.Serializable

@Serializable
enum class Severity(val label: String, val rank: Int) {
    INFO("Info", 0),
    LOW("Low", 1),
    MEDIUM("Medium", 2),
    HIGH("High", 3),
    CRITICAL("Critical", 4),
}

/**
 * One observation. Findings are append-only and timestamped at creation so the evidence log
 * reflects when something was actually seen, not when it was written out.
 */
@Serializable
data class Finding(
    val moduleId: String,
    val observedAtEpochMs: Long,
    val severity: Severity,
    val title: String,
    val subject: String,
    val detail: String,
    val data: Map<String, String> = emptyMap(),
)
