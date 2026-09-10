package dev.cyphernova.mobileops.modules.tier0

import android.Manifest
import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule
import kotlinx.coroutines.delay

/**
 * Enumerates every AP in earshot and audits what each one advertises. Entirely passive: the
 * radio stays in managed mode and we only read beacons already being broadcast.
 */
class WifiSurveyModule : PentestModule {
    override val id = "t0.wifi.survey"
    override val title = "WiFi survey & AP audit"
    override val description =
        "Grades each access point's advertised security: encryption suite, WPS exposure, management " +
            "frame protection, hidden SSIDs. Audits the selected networks, or everything in range if " +
            "nothing is selected."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.PASSIVE
    override val requiredPermissions = listOf(Manifest.permission.ACCESS_FINE_LOCATION)

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val radio = WifiRadio(context.androidContext)
        if (!radio.isWifiEnabled) {
            return ModuleOutcome.Blocked("WiFi is switched off; the platform will not return scan results.")
        }

        // Ask for a refresh, then give the supplicant a moment. A throttled request is fine —
        // we fall back to the platform's cached results rather than failing the run.
        radio.requestScan()
        delay(SCAN_SETTLE_MS)

        val visible = radio.latestResults()
        if (visible.isEmpty()) {
            return ModuleOutcome.Failed(
                "No scan results. Location services must be on device-wide, not just granted to the app.",
            )
        }

        // The radio always hears the whole room — that is how RF works, and nothing an app does
        // changes it. What the selection controls is what gets audited and written to the log.
        val selected = context.targets.networks()
        val observations = if (selected.isEmpty()) {
            visible
        } else {
            val wanted = selected.map { it.bssid.uppercase() }.toSet()
            visible.filter { it.bssid.uppercase() in wanted }
        }

        if (observations.isEmpty()) {
            return ModuleOutcome.Blocked(
                "None of the ${selected.size} selected network(s) are in range of the latest scan.",
            )
        }

        var flagged = 0

        observations.sortedByDescending { it.rssiDbm }.forEach { ap ->
            val profile = ApSecurityAnalyser.analyse(ap)
            val facts = mapOf(
                "bssid" to ap.bssid,
                "band" to ap.band,
                "channel" to ap.channel.toString(),
                "rssi_dbm" to ap.rssiDbm.toString(),
                "encryption" to profile.encryption.label,
                "wps" to profile.wpsEnabled.toString(),
                "pmf" to profile.managementFrameProtection.toString(),
                "raw_capabilities" to ap.capabilities,
            )

            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    severity = Severity.INFO,
                    title = "AP observed: ${ap.displaySsid}",
                    subject = ap.bssid,
                    detail = "${profile.encryption.label} on ${ap.band} channel ${ap.channel} at ${ap.rssiDbm} dBm.",
                    data = facts,
                ),
            )

            profile.issues.forEach { issue ->
                flagged++
                emit(
                    Finding(
                        moduleId = id,
                        observedAtEpochMs = System.currentTimeMillis(),
                        severity = issue.severity,
                        title = "${issue.title} — ${ap.displaySsid}",
                        subject = ap.bssid,
                        detail = issue.detail,
                        data = facts,
                    ),
                )
            }
        }

        return ModuleOutcome.Completed(
            if (selected.isEmpty()) {
                "${observations.size} AP(s) observed, $flagged weakness(es) flagged."
            } else {
                "${observations.size} selected AP(s) audited of ${visible.size} in range, " +
                    "$flagged weakness(es) flagged."
            },
        )
    }

    private companion object {
        const val SCAN_SETTLE_MS = 2_500L
    }
}
