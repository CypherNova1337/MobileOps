package dev.cyphernova.mobileops.modules.tier0

import android.Manifest
import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.exploit.WpsPin
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleCategory
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
                "rssi_dbm" to if (ap.hasRssi) ap.rssiDbm.toString() else "withheld",
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
                    detail = "${profile.encryption.label} on ${ap.band} channel ${ap.channel}, ${ap.rssiLabel}.",
                    data = facts,
                ),
            )

            // Elements carry what the capability string cannot: whether WPS is locked, the exact
            // AKM list, whether 802.11w is required or merely offered.
            val beacon = BeaconAudit.profileOf(ap)
            val beaconIssues = beacon?.let(BeaconAudit::issues).orEmpty()

            if (beacon != null) {
                emit(
                    Finding(
                        moduleId = id,
                        observedAtEpochMs = System.currentTimeMillis(),
                        severity = Severity.INFO,
                        title = "Beacon elements: ${ap.displaySsid}",
                        subject = ap.bssid,
                        detail = buildString {
                            append("Radio: ${BeaconAudit.radioSummary(beacon)}. ")
                            beacon.rsn?.let { rsn ->
                                append("RSN: AKM ${rsn.akmSuites.joinToString().ifBlank { "none" }}, ")
                                append("pairwise ${rsn.pairwiseCiphers.joinToString().ifBlank { "none" }}, ")
                                append("group ${rsn.groupCipher}, ")
                                append(
                                    when {
                                        rsn.managementFrameProtectionRequired -> "802.11w required. "
                                        rsn.managementFrameProtectionCapable -> "802.11w optional. "
                                        else -> "no 802.11w. "
                                    },
                                )
                            }
                            beacon.wps?.let { wps ->
                                append("WPS ${wps.version ?: "?"}, ")
                                append(
                                    when (wps.setupLocked) {
                                        true -> "PIN locked. "
                                        false -> "PIN unlocked. "
                                        null -> "lock state not advertised. "
                                    },
                                )
                                wps.deviceName?.let { append("Device '$it'. ") }
                            }
                        },
                        data = buildMap {
                            put("elements", beacon.elementIds.joinToString())
                            put("vendor_ouis", beacon.vendorOuis.joinToString())
                            beacon.rsn?.let {
                                put("akm_suites", it.akmSuites.joinToString())
                                put("pairwise_ciphers", it.pairwiseCiphers.joinToString())
                                put("group_cipher", it.groupCipher)
                                put("mfp_required", it.managementFrameProtectionRequired.toString())
                                put("mfp_capable", it.managementFrameProtectionCapable.toString())
                            }
                            beacon.wps?.let {
                                put("wps_version", it.version.orEmpty())
                                put("wps_locked", it.setupLocked?.toString().orEmpty())
                                put("wps_configured", it.configured?.toString().orEmpty())
                                put("wps_manufacturer", it.manufacturer.orEmpty())
                                put("wps_model", it.modelName.orEmpty())
                                put("wps_model_number", it.modelNumber.orEmpty())
                                put("wps_serial", it.serialNumber.orEmpty())
                                put("wps_device_name", it.deviceName.orEmpty())
                            }
                        },
                    ),
                )
            }

            if (profile.wpsEnabled) emit(pinCandidates(ap, beacon?.wps?.setupLocked, facts))

            (profile.issues + beaconIssues).forEach { issue ->
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

    /**
     * Computes the default PINs this AP is likely to be using, from its BSSID.
     *
     * A long line of consumer firmware generated the WPS PIN on the sticker from the MAC address
     * with a published function, which means the "secret" is derivable by anyone who can hear the
     * beacon. Working the candidates out here, off-network, is what lets the registrar attack run
     * as a handful of attempts instead of eleven thousand once there is a route to the device.
     *
     * A radio-side PIN lock does not close this: the UPnP registrar path ignores it entirely.
     */
    private fun pinCandidates(
        ap: ApObservation,
        setupLocked: Boolean?,
        facts: Map<String, String>,
    ): Finding {
        val candidates = WpsPin.candidatesFor(ap.bssid)
        val derived = candidates.filter { it.algorithm != "known default" }

        return Finding(
            moduleId = id,
            observedAtEpochMs = System.currentTimeMillis(),
            severity = Severity.HIGH,
            title = "WPS default PIN candidates — ${ap.displaySsid}",
            subject = ap.bssid,
            detail = buildString {
                append(
                    "The PIN on this AP's sticker is derivable from its BSSID on any firmware " +
                        "that used a published default-PIN function, which most consumer routers " +
                        "of the WPS era did. ${derived.size} candidate(s) computed from " +
                        "${ap.bssid}, plus ${candidates.size - derived.size} fixed defaults: ",
                )
                append(candidates.take(6).joinToString { "${it.pin} (${it.algorithm})" })
                append(". ")
                when (setupLocked) {
                    true -> append(
                        "The beacon says AP Setup Locked, so PIN attempts over the air are " +
                            "refused — but that lock lives in the radio path and does not apply " +
                            "to the registrar exposed over UPnP. ",
                    )
                    false -> append("The AP is not advertising a setup lock, so PIN attempts are accepted. ")
                    null -> Unit
                }
                append(
                    "Run the WPS registrar attack once there is a route to this device to test " +
                        "them; it will try these first.",
                )
            },
            data = facts + mapOf(
                "pin_candidates" to candidates.take(12).joinToString { it.pin },
                "pin_algorithms" to derived.joinToString { "${it.algorithm}=${it.pin}" },
                "wps_setup_locked" to setupLocked?.toString().orEmpty(),
            ),
        )
    }

    private companion object {
        const val SCAN_SETTLE_MS = 2_500L
    }
}
