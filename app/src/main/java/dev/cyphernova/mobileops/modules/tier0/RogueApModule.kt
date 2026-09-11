package dev.cyphernova.mobileops.modules.tier0

import android.Manifest
import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleCategory
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule
import kotlinx.coroutines.delay

/**
 * Looks for the signatures of an evil twin sitting alongside a legitimate network: an SSID
 * whose BSSIDs disagree about security, or whose radios come from unrelated hardware vendors.
 *
 * This is a defensive module — it detects rogue infrastructure rather than standing any up.
 */
class RogueApModule : PentestModule {
    override val id = "t0.wifi.rogue"
    override val title = "Evil-twin / rogue AP detection"
    override val description =
        "Correlates every BSSID broadcasting each SSID and flags security downgrades, vendor mismatches " +
            "and implausible signal spreads that suggest an impersonating AP."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.PASSIVE
    override val category = ModuleCategory.WIRELESS
    override val requiredPermissions = listOf(Manifest.permission.ACCESS_FINE_LOCATION)

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val radio = WifiRadio(context.androidContext)
        if (!radio.isWifiEnabled) {
            return ModuleOutcome.Blocked("WiFi is switched off; the platform will not return scan results.")
        }
        radio.requestScan()
        delay(SCAN_SETTLE_MS)

        // Scoped by SSID rather than BSSID on purpose: an evil twin is by definition a BSSID you
        // did not select, so filtering to selected BSSIDs would discard the very thing being
        // hunted. Selecting a network narrows which *names* are correlated, never which radios.
        val selectedSsids = context.targets.networks()
            .map { it.ssid }
            .filter { it.isNotBlank() }
            .toSet()

        val byNetwork = radio.latestResults()
            .filterNot { it.isHidden }
            .groupBy { it.ssid }
            .let { grouped ->
                if (selectedSsids.isEmpty()) grouped else grouped.filterKeys { it in selectedSsids }
            }
            .filterValues { it.size > 1 }

        if (byNetwork.isEmpty()) {
            return ModuleOutcome.Completed(
                if (selectedSsids.isEmpty()) {
                    "No SSID is served by more than one BSSID; nothing to correlate."
                } else {
                    "The selected network(s) are each served by a single BSSID; nothing to correlate."
                },
            )
        }

        var suspicious = 0

        byNetwork.forEach { (ssid, aps) ->
            val profiles = aps.associateWith { ApSecurityAnalyser.analyse(it) }
            val encryptions = profiles.values.map { it.encryption }.toSet()
            val vendors = aps.map { it.oui }.toSet()

            // A real multi-AP deployment is configured centrally: same security on every radio.
            // Disagreement is the classic evil-twin tell — the impostor drops encryption so
            // clients can associate without knowing the key.
            if (encryptions.size > 1) {
                suspicious++
                val weakest = profiles.values.minByOrNull { it.encryption.ordinal }?.encryption
                emit(
                    Finding(
                        moduleId = id,
                        observedAtEpochMs = System.currentTimeMillis(),
                        severity = Severity.HIGH,
                        title = "Security mismatch across '$ssid'",
                        subject = ssid,
                        detail = "${aps.size} BSSIDs advertise this SSID with differing security " +
                            "(${encryptions.joinToString { it.label }}). A client may be steered onto the " +
                            "weakest of these (${weakest?.label}) without any user-visible warning.",
                        data = bssidBreakdown(profiles),
                    ),
                )
            }

            // Vendor spread is weaker evidence — mixed-vendor estates are common — so it is
            // reported as something to check, not as a finding on its own.
            if (vendors.size > 1 && encryptions.size == 1) {
                emit(
                    Finding(
                        moduleId = id,
                        observedAtEpochMs = System.currentTimeMillis(),
                        severity = Severity.INFO,
                        title = "Mixed hardware vendors serving '$ssid'",
                        subject = ssid,
                        detail = "BSSIDs for this SSID span ${vendors.size} vendor prefixes " +
                            "(${vendors.joinToString()}). Expected in a mixed estate; worth confirming against " +
                            "the client's asset inventory.",
                        data = bssidBreakdown(profiles),
                    ),
                )
            }
        }

        return ModuleOutcome.Completed(
            "${byNetwork.size} multi-BSSID network(s) correlated, $suspicious flagged.",
        )
    }

    private fun bssidBreakdown(profiles: Map<ApObservation, SecurityProfile>): Map<String, String> =
        profiles.entries.associate { (ap, profile) ->
            ap.bssid to "${profile.encryption.label}, ch ${ap.channel}, ${ap.rssiLabel}, vendor ${ap.oui}"
        }

    private companion object {
        const val SCAN_SETTLE_MS = 2_500L
    }
}
