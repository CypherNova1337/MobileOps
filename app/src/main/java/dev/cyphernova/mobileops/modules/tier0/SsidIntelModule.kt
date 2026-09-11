package dev.cyphernova.mobileops.modules.tier0

import android.Manifest
import dev.cyphernova.mobileops.core.beacon.OuiLookup
import dev.cyphernova.mobileops.core.beacon.SsidIntel
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
 * Reads the network names in range for what they give away.
 *
 * This is the cheapest intelligence in the whole tool and among the most useful. An SSID is
 * broadcast to the street continuously; it costs nothing to collect and frequently identifies
 * the router vendor, the ISP, the kind of device behind it, the owner by name, and whether
 * anybody ever opened the admin interface. None of it requires association, a passphrase or a
 * working network.
 *
 * One finding per network that has something to say, plus a rollup — the analysis is offline and
 * could generate a note for every AP in range, which would bury the ones that matter.
 */
class SsidIntelModule : PentestModule {
    override val id = "t0.wifi.ssidintel"
    override val title = "Network name intelligence"
    override val description =
        "Reads every SSID in range for factory defaults, ISP equipment, device types, network " +
            "roles and personal names. Pure offline analysis — needs no network."
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
            return ModuleOutcome.Blocked("WiFi must be on to hear beacons, though nothing is joined.")
        }

        radio.requestScan()
        delay(SCAN_SETTLE_MS)

        // One entry per name: the same network on 2.4 and 5 GHz is one finding, not two.
        val byName = radio.latestResults()
            .filter { it.ssid.isNotBlank() }
            .groupBy { it.ssid }

        if (byName.isEmpty()) {
            return ModuleOutcome.Failed(
                "No named networks heard. Hidden APs broadcast no name to analyse.",
            )
        }

        val analysed = byName.mapValues { (ssid, _) -> SsidIntel.classify(ssid) }
        val interesting = analysed.filterValues { it.isNotEmpty() }

        emitRollup(byName.keys, analysed, emit)
        interesting.forEach { (ssid, notes) ->
            emit(networkFinding(ssid, notes, byName.getValue(ssid)))
        }

        return ModuleOutcome.Completed(
            "${byName.size} named network(s); ${interesting.size} disclose something.",
        )
    }

    private suspend fun emitRollup(
        names: Set<String>,
        analysed: Map<String, List<SsidIntel.Note>>,
        emit: suspend (Finding) -> Unit,
    ) {
        val factory = names.filter(SsidIntel::isFactoryDefault)
        val vendors = factory.mapNotNull(SsidIntel::vendorFromSsid).distinct()
        val concerns = analysed.values.flatten().count { it.weight == SsidIntel.Weight.CONCERN }

        emit(
            Finding(
                moduleId = id,
                observedAtEpochMs = System.currentTimeMillis(),
                severity = if (factory.isNotEmpty()) Severity.LOW else Severity.INFO,
                title = "Name analysis: ${names.size} network(s)",
                subject = "RF environment",
                detail = buildString {
                    append("${factory.size} still carry an unchanged factory SSID")
                    if (vendors.isNotEmpty()) append(" (${vendors.joinToString()})")
                    append(", $concerns name(s) raise something worth following up. ")
                    append(
                        "A factory name is not proof of a weak key, but it is strong evidence " +
                            "nobody opened the admin interface — which is where the default " +
                            "administrative password still is.",
                    )
                },
                data = mapOf(
                    "networks" to names.size.toString(),
                    "factory_defaults" to factory.size.toString(),
                    "factory_vendors" to vendors.joinToString(),
                    "concerns" to concerns.toString(),
                ),
            ),
        )
    }

    private fun networkFinding(
        ssid: String,
        notes: List<SsidIntel.Note>,
        radios: List<ApObservation>,
    ): Finding {
        val strongest = radios.maxByOrNull { if (it.hasRssi) it.rssiDbm else Int.MIN_VALUE }
        val concern = notes.any { it.weight == SsidIntel.Weight.CONCERN }

        return Finding(
            moduleId = id,
            observedAtEpochMs = System.currentTimeMillis(),
            severity = if (concern) Severity.LOW else Severity.INFO,
            title = "Name discloses: $ssid",
            subject = ssid,
            detail = buildString {
                notes.forEach { note -> append("${note.label}. ${note.detail} ") }
                append(
                    "Heard on ${radios.size} radio(s): " +
                        radios.joinToString { "${it.bssid} (${it.band} ch ${it.channel})" },
                )
                strongest?.let { append(", strongest ${it.rssiLabel}.") }
            },
            data = mapOf(
                "ssid" to ssid,
                "notes" to notes.joinToString { it.label },
                "factory_default" to SsidIntel.isFactoryDefault(ssid).toString(),
                "implied_vendor" to SsidIntel.vendorFromSsid(ssid).orEmpty(),
                "bssids" to radios.joinToString { it.bssid },
                "oui_vendor" to radios.joinToString { OuiLookup.describe(it.bssid) },
            ),
        )
    }

    private companion object {
        const val SCAN_SETTLE_MS = 5_000L
    }
}
