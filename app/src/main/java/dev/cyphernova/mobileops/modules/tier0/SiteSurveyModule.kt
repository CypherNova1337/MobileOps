package dev.cyphernova.mobileops.modules.tier0

import android.Manifest
import dev.cyphernova.mobileops.core.beacon.OuiLookup
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
 * Surveys the whole RF environment over several scans, without joining anything.
 *
 * Nothing here needs association, or even a usable network: an AP broadcasts its identity,
 * security and capabilities to everyone in range, continuously. That makes this the module to
 * run while walking a building, sitting in a car park, or standing in a client's lobby before
 * anyone has handed over a passphrase.
 *
 * Scans are repeated rather than taken once, because a single scan misses APs that were briefly
 * quiet and gives no idea whether a signal is steady or a device passing through.
 */
class SiteSurveyModule : PentestModule {
    override val id = "t0.wifi.sitesurvey"
    override val title = "RF site survey"
    override val description =
        "Sweeps the whole RF environment over repeated scans: every AP in range, vendors, channel " +
            "congestion and a security census. Needs no network — works while walking around."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.PASSIVE
    override val category = ModuleCategory.WIRELESS
    override val requiredPermissions = listOf(Manifest.permission.ACCESS_FINE_LOCATION)

    /** What repeated scans established about one radio. */
    private data class Seen(
        val observation: ApObservation,
        var sightings: Int,
        var strongest: Int,
        var weakest: Int,
    )

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val radio = WifiRadio(context.androidContext)
        if (!radio.isWifiEnabled) {
            return ModuleOutcome.Blocked(
                "WiFi is switched off. It does not need to be connected to anything, but the radio " +
                    "has to be on to hear beacons.",
            )
        }

        val seen = mutableMapOf<String, Seen>()

        // Android 10+ allows a foreground app four scans per two-minute window; asking for more
        // silently returns the same cached results, so the budget is spent deliberately.
        repeat(SCAN_ROUNDS) { round ->
            radio.requestScan()
            delay(SCAN_INTERVAL_MS)

            radio.latestResults().forEach { ap ->
                if (ap.bssid.isBlank()) return@forEach
                val existing = seen[ap.bssid]
                if (existing == null) {
                    seen[ap.bssid] = Seen(ap, 1, ap.rssiDbm, ap.rssiDbm)
                } else {
                    existing.sightings++
                    if (ap.hasRssi) {
                        existing.strongest = maxOf(existing.strongest, ap.rssiDbm)
                        existing.weakest = minOf(existing.weakest, ap.rssiDbm)
                    }
                }
            }
        }

        if (seen.isEmpty()) {
            return ModuleOutcome.Failed(
                "No APs heard. Location services must be on device-wide, not just granted to the app.",
            )
        }

        val all = seen.values.toList()
        emitCensus(all, emit)
        emitChannelUse(all, emit)
        emitVendors(all, emit)
        emitNotableAps(all, emit)

        return ModuleOutcome.Completed("${all.size} AP(s) across $SCAN_ROUNDS scan(s).")
    }

    private suspend fun emitCensus(all: List<Seen>, emit: suspend (Finding) -> Unit) {
        val profiles = all.associateWith { ApSecurityAnalyser.analyse(it.observation) }
        val byEncryption = profiles.values.groupingBy { it.encryption.label }.eachCount()
        val open = profiles.count { it.value.encryption == Encryption.OPEN }
        val wps = profiles.count { it.value.wpsEnabled }
        val noPmf = profiles.count { !it.value.managementFrameProtection }

        emit(
            Finding(
                moduleId = id,
                observedAtEpochMs = System.currentTimeMillis(),
                severity = Severity.INFO,
                title = "Site survey: ${all.size} AP(s) in range",
                subject = "RF environment",
                detail = buildString {
                    append("Security across everything heard: ")
                    append(byEncryption.entries.sortedByDescending { it.value }
                        .joinToString { "${it.value}× ${it.key}" })
                    append(". $wps advertise WPS, $noPmf lack management frame protection.")
                    append(" ${all.count { it.observation.isHidden }} hide their SSID.")
                },
                data = mapOf(
                    "ap_count" to all.size.toString(),
                    "open" to open.toString(),
                    "wps_enabled" to wps.toString(),
                    "no_pmf" to noPmf.toString(),
                    "encryption_breakdown" to byEncryption.entries.joinToString { "${it.key}=${it.value}" },
                ),
            ),
        )
    }

    /**
     * 2.4 GHz channels overlap: only 1, 6 and 11 are non-overlapping, so anything elsewhere
     * interferes with two neighbours at once. That is a performance finding an off-network
     * survey can make without touching anything.
     */
    private suspend fun emitChannelUse(all: List<Seen>, emit: suspend (Finding) -> Unit) {
        val byChannel = all.groupBy { it.observation.channel }.filterKeys { it > 0 }
        if (byChannel.isEmpty()) return

        val crowded = byChannel.maxByOrNull { it.value.size }
        val overlapping = all.filter { it.observation.frequencyMhz in 2401..2495 }
            .filter { it.observation.channel !in NON_OVERLAPPING_24 }

        emit(
            Finding(
                moduleId = id,
                observedAtEpochMs = System.currentTimeMillis(),
                severity = if (overlapping.size > 2) Severity.LOW else Severity.INFO,
                title = "Channel usage across ${byChannel.size} channel(s)",
                subject = "RF environment",
                detail = buildString {
                    append("Occupancy: ")
                    append(byChannel.entries.sortedBy { it.key }
                        .joinToString { "ch ${it.key}: ${it.value.size}" })
                    crowded?.let { append(". Busiest is channel ${it.key} with ${it.value.size} AP(s)") }
                    if (overlapping.isNotEmpty()) {
                        append(
                            ". ${overlapping.size} AP(s) sit on overlapping 2.4 GHz channels — only " +
                                "1, 6 and 11 avoid interfering with their neighbours",
                        )
                    }
                    append(".")
                },
                data = mapOf(
                    "channels" to byChannel.entries.sortedBy { it.key }
                        .joinToString { "${it.key}=${it.value.size}" },
                    "overlapping_24ghz" to overlapping.size.toString(),
                ),
            ),
        )
    }

    private suspend fun emitVendors(all: List<Seen>, emit: suspend (Finding) -> Unit) {
        val byVendor = all.groupingBy { OuiLookup.describe(it.observation.bssid) }.eachCount()
        val randomised = all.filter { OuiLookup.isLocallyAdministered(it.observation.bssid) }

        emit(
            Finding(
                moduleId = id,
                observedAtEpochMs = System.currentTimeMillis(),
                // An AP with a randomised BSSID is not normal — infrastructure does not randomise,
                // so it is either a phone hotspot or something trying not to be identified.
                severity = if (randomised.isNotEmpty()) Severity.LOW else Severity.INFO,
                title = "Equipment vendors in range",
                subject = "RF environment",
                detail = buildString {
                    append(byVendor.entries.sortedByDescending { it.value }
                        .joinToString { "${it.value}× ${it.key}" })
                    if (randomised.isNotEmpty()) {
                        append(
                            ". ${randomised.size} AP(s) use a locally-administered BSSID: " +
                                "infrastructure does not randomise its address, so these are phone " +
                                "hotspots or deliberately anonymised radios",
                        )
                    }
                    append(".")
                },
                data = mapOf(
                    "vendors" to byVendor.entries.joinToString { "${it.key}=${it.value}" },
                    "randomised_bssids" to randomised.size.toString(),
                ),
            ),
        )
    }

    /** Only the APs worth a second look get their own finding; the rest stay in the census. */
    private suspend fun emitNotableAps(all: List<Seen>, emit: suspend (Finding) -> Unit) {
        all.forEach { entry ->
            val ap = entry.observation
            val profile = ApSecurityAnalyser.analyse(ap)
            val reasons = buildList {
                if (profile.encryption == Encryption.OPEN) add("open, no encryption at all")
                if (profile.encryption == Encryption.WEP) add("WEP, which is broken")
                if (profile.wpsEnabled) add("WPS advertised")
                if (OuiLookup.isLocallyAdministered(ap.bssid)) add("randomised BSSID")
            }
            if (reasons.isEmpty()) return@forEach

            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    severity = when {
                        profile.encryption == Encryption.WEP -> Severity.HIGH
                        profile.encryption == Encryption.OPEN -> Severity.MEDIUM
                        else -> Severity.LOW
                    },
                    title = "Notable AP: ${ap.displaySsid}",
                    subject = ap.bssid,
                    detail = "${reasons.joinToString("; ")}. " +
                        "${OuiLookup.describe(ap.bssid)}, ${ap.band} channel ${ap.channel}, " +
                        "${ap.rssiLabel}, seen ${entry.sightings} of $SCAN_ROUNDS scan(s)" +
                        if (entry.strongest != entry.weakest) {
                            " (${entry.weakest} to ${entry.strongest} dBm)."
                        } else {
                            "."
                        },
                    data = mapOf(
                        "bssid" to ap.bssid,
                        "vendor" to OuiLookup.describe(ap.bssid),
                        "channel" to ap.channel.toString(),
                        "encryption" to profile.encryption.label,
                        "sightings" to entry.sightings.toString(),
                        "rssi_max" to entry.strongest.toString(),
                        "rssi_min" to entry.weakest.toString(),
                    ),
                ),
            )
        }
    }

    private companion object {
        /** Matches the platform's four-per-two-minute allowance rather than fighting it. */
        const val SCAN_ROUNDS = 4
        const val SCAN_INTERVAL_MS = 7_000L
        val NON_OVERLAPPING_24 = setOf(1, 6, 11, 14)
    }
}
