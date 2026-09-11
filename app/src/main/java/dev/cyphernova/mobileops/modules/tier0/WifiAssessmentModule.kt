package dev.cyphernova.mobileops.modules.tier0

import android.Manifest
import android.content.Context
import android.net.wifi.WifiManager
import dev.cyphernova.mobileops.core.attack.AttackPath
import dev.cyphernova.mobileops.core.beacon.BeaconProfile
import dev.cyphernova.mobileops.core.beacon.SsidIntel
import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.crack.CaptureFormats
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
 * Assesses one network and says how it would be entered.
 *
 * This is the module a WiFi engagement actually runs. The rest of the wireless set answers
 * questions — what is in range, what does this beacon say, what is this name — and leaves the
 * operator to assemble an answer out of twenty findings spread across four modules, most of them
 * about networks nobody is testing. This one takes the selected network, gathers everything the
 * others would have found about it, and produces the thing a report is for: the routes in,
 * ranked, each with what it costs and what is standing in the way.
 *
 * It is scoped to a selected target by design. A survey that generates attack material for every
 * AP in earshot produces a report full of other people's networks, which is noise at best.
 */
class WifiAssessmentModule : PentestModule {
    override val id = "t0.wifi.assess"
    override val title = "Assess target network"
    override val description =
        "The main event. Takes the selected network, gathers everything passively observable " +
            "about it, and reports how it would be entered — every route ranked, with what each " +
            "one needs and what is blocking it."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.PASSIVE
    override val category = ModuleCategory.WIRELESS
    override val requiredPermissions = listOf(Manifest.permission.ACCESS_FINE_LOCATION)
    override val requiresTarget = true

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val selected = context.targets.networks()
        if (selected.isEmpty()) {
            return ModuleOutcome.Blocked(
                "No network selected. Pick the one you are testing on the Targets tab — this " +
                    "module reports on that network rather than on everything in earshot.",
            )
        }

        val radio = WifiRadio(context.androidContext)
        if (!radio.isWifiEnabled) {
            return ModuleOutcome.Blocked("WiFi must be on to hear beacons, though nothing is joined.")
        }

        radio.requestScan()
        delay(SCAN_SETTLE_MS)
        val visible = radio.latestResults()

        var assessed = 0
        var reachable = 0

        for (network in selected) {
            val radios = visible.filter { it.ssid == network.ssid && it.ssid.isNotBlank() }
                .ifEmpty { visible.filter { it.bssid.equals(network.bssid, ignoreCase = true) } }

            if (radios.isEmpty()) {
                emit(
                    Finding(
                        moduleId = id,
                        observedAtEpochMs = System.currentTimeMillis(),
                        severity = Severity.INFO,
                        title = "${network.label} is not in range",
                        subject = network.bssid,
                        detail = "The latest scan did not hear this network, so there is nothing " +
                            "current to assess. Move into range and run again.",
                    ),
                )
                continue
            }

            assessed++
            // An SSID on several radios is one network. Assess the strongest, since that is the
            // one an attack would actually be run against, but report the whole footprint.
            val strongest = radios.maxByOrNull { if (it.hasRssi) it.rssiDbm else Int.MIN_VALUE }!!
            if (assess(context, strongest, radios, emit)) reachable++
        }

        return when {
            assessed == 0 -> ModuleOutcome.Completed("No selected network was in range.")
            reachable > 0 -> ModuleOutcome.Completed(
                "$assessed network(s) assessed; $reachable has a route open from this handset.",
            )
            else -> ModuleOutcome.Completed(
                "$assessed network(s) assessed; no route open from this handset as it stands.",
            )
        }
    }

    private suspend fun assess(
        context: ModuleContext,
        ap: ApObservation,
        radios: List<ApObservation>,
        emit: suspend (Finding) -> Unit,
    ): Boolean {
        val profile = ApSecurityAnalyser.analyse(ap)
        val beacon = BeaconAudit.profileOf(ap)
        val target = describe(context, ap, profile, beacon)
        val routes = AttackPath.routesFor(target)
        val open = routes.count { it.viability == AttackPath.Viability.OPEN }

        emit(verdictFinding(ap, radios, profile, target, routes, open))

        // The routes that are not open are the useful half of the answer — they say what would
        // change it — so they are reported rather than filtered out.
        routes.filter { it.viability != AttackPath.Viability.NOT_APPLICABLE }
            .forEach { route -> emit(routeFinding(ap, route)) }

        if (target.wpsAdvertised) emit(pinFinding(ap, target))

        return open > 0
    }

    /** Folds everything passively known about one radio into the analysis's input. */
    private fun describe(
        context: ModuleContext,
        ap: ApObservation,
        profile: SecurityProfile,
        beacon: BeaconProfile?,
    ): AttackPath.Target {
        // SAE with no PSK alongside it is the case offline recovery cannot touch. Transition
        // mode lists both, and is therefore still a passphrase target. The RSN element is the
        // authority here; the capability string cannot tell the two apart reliably.
        val rsn = beacon?.rsn
        val saeOnly = when {
            rsn != null -> rsn.usesSae && !rsn.usesPsk
            else -> profile.encryption == Encryption.WPA3
        }

        return AttackPath.Target(
            ssid = ap.displaySsid,
            bssid = ap.bssid,
            isOpen = profile.encryption == Encryption.OPEN,
            isWep = profile.encryption == Encryption.WEP,
            hasPresharedKey = profile.encryption in PSK_ENCRYPTIONS && !saeOnly,
            isSaeOnly = saeOnly,
            isEnterprise = rsn?.usesEnterprise == true || profile.encryption in ENTERPRISE_ENCRYPTIONS,
            wpsAdvertised = profile.wpsEnabled,
            wpsPinLocked = beacon?.wps?.setupLocked,
            wpsPushButtonActive = beacon?.wps?.pushButtonActive == true,
            managementFrameProtectionRequired = rsn?.managementFrameProtectionRequired == true,
            factoryDefaultSsid = SsidIntel.isFactoryDefault(ap.ssid),
            haveCapture = haveCaptureFor(context.androidContext, ap.ssid),
            haveLanAccess = associatedWith(context.androidContext, ap.ssid),
        )
    }

    private fun verdictFinding(
        ap: ApObservation,
        radios: List<ApObservation>,
        profile: SecurityProfile,
        target: AttackPath.Target,
        routes: List<AttackPath.Route>,
        open: Int,
    ) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        // The verdict carries the weight of the assessment, so its severity is the assessment's.
        severity = when {
            open > 0 -> Severity.CRITICAL
            routes.any { it.viability == AttackPath.Viability.NEEDS_ACCESS } -> Severity.HIGH
            routes.any { it.viability == AttackPath.Viability.NEEDS_CAPTURE } -> Severity.MEDIUM
            else -> Severity.LOW
        },
        title = "Assessment: ${ap.displaySsid}",
        subject = ap.bssid,
        detail = buildString {
            append(AttackPath.verdict(target))
            append("\n\n")
            append("${profile.encryption.label}")
            append(", ${radios.size} radio(s): ")
            append(radios.joinToString { "${it.bssid} ${it.band} ch ${it.channel} ${it.rssiLabel}" })
            append(". 802.11w ")
            append(
                when {
                    target.managementFrameProtectionRequired -> "required"
                    profile.managementFrameProtection -> "offered but not required"
                    else -> "absent"
                },
            )
            append(if (target.wpsAdvertised) ", WPS advertised" else ", no WPS")
            append(if (target.factoryDefaultSsid) ", factory SSID unchanged" else "")
            append(".")
        },
        data = mapOf(
            "ssid" to ap.ssid,
            "bssid" to ap.bssid,
            "encryption" to profile.encryption.label,
            "routes_open" to open.toString(),
            "routes_needing_access" to
                routes.count { it.viability == AttackPath.Viability.NEEDS_ACCESS }.toString(),
            "routes_needing_capture" to
                routes.count { it.viability == AttackPath.Viability.NEEDS_CAPTURE }.toString(),
            "have_capture" to target.haveCapture.toString(),
            "have_lan_access" to target.haveLanAccess.toString(),
            "pmf_required" to target.managementFrameProtectionRequired.toString(),
        ),
    )

    private fun routeFinding(ap: ApObservation, route: AttackPath.Route) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = when (route.viability) {
            AttackPath.Viability.OPEN -> Severity.CRITICAL
            AttackPath.Viability.NEEDS_ACCESS -> Severity.HIGH
            AttackPath.Viability.NEEDS_CAPTURE -> Severity.MEDIUM
            else -> Severity.INFO
        },
        title = "${route.viability.label}: ${route.name} — ${ap.displaySsid}",
        subject = ap.bssid,
        detail = buildString {
            append(route.rationale)
            route.requires?.let { append("\n\nNeeds: $it") }
            route.module?.let { append("\n\nModule: $it") }
        },
        data = mapOf(
            "route" to route.name,
            "viability" to route.viability.name,
            "module" to route.module.orEmpty(),
            "ssid" to ap.ssid,
        ),
    )

    private fun pinFinding(ap: ApObservation, target: AttackPath.Target): Finding {
        val candidates = WpsPin.candidatesFor(ap.bssid)
        val derived = candidates.filter { it.algorithm != "known default" }
        return Finding(
            moduleId = id,
            observedAtEpochMs = System.currentTimeMillis(),
            severity = Severity.HIGH,
            title = "WPS PIN candidates — ${ap.displaySsid}",
            subject = ap.bssid,
            detail = "A long line of consumer firmware generated the PIN on the sticker from the " +
                "MAC address with a published function, so it is computable rather than " +
                "guessable. ${derived.size} derived from ${ap.bssid}, plus " +
                "${candidates.size - derived.size} fixed vendor defaults. Top candidates: " +
                candidates.take(6).joinToString { "${it.pin} (${it.algorithm})" } +
                ". The registrar module tries these first, in this order.",
            data = mapOf(
                "bssid" to ap.bssid,
                "pin_candidates" to candidates.take(12).joinToString { it.pin },
                "pin_algorithms" to derived.joinToString { "${it.algorithm}=${it.pin}" },
                "wps_setup_locked" to target.wpsPinLocked?.toString().orEmpty(),
            ),
        )
    }

    /** Whether a capture for this SSID is already sitting in the handshakes folder. */
    private fun haveCaptureFor(context: Context, ssid: String): Boolean {
        if (ssid.isBlank()) return false
        val directory = context.getExternalFilesDir(CAPTURE_DIR) ?: return false
        return directory.listFiles().orEmpty().any { file ->
            runCatching {
                when {
                    file.name.endsWith(".hccapx", ignoreCase = true) ->
                        CaptureFormats.parseHccapx(file.readBytes())
                    else -> CaptureFormats.parse22000(file.readText())
                }.any { it.ssid == ssid }
            }.getOrDefault(false)
        }
    }

    /** Whether this handset already has an IP on the target, which opens the LAN-side routes. */
    @Suppress("DEPRECATION")
    private fun associatedWith(context: Context, ssid: String): Boolean {
        if (ssid.isBlank()) return false
        val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            ?: return false
        val connected = runCatching { wifi.connectionInfo?.ssid }.getOrNull() ?: return false
        // WifiInfo quotes the SSID, and an unavailable one comes back as a literal placeholder.
        return connected.trim('"') == ssid
    }

    private companion object {
        const val SCAN_SETTLE_MS = 3_000L
        const val CAPTURE_DIR = "handshakes"

        val PSK_ENCRYPTIONS = setOf(
            Encryption.WPA,
            Encryption.WPA2,
            Encryption.WPA3_TRANSITION,
        )
        val ENTERPRISE_ENCRYPTIONS = setOf(
            Encryption.WPA2_ENTERPRISE,
            Encryption.WPA3_ENTERPRISE,
        )
    }
}
