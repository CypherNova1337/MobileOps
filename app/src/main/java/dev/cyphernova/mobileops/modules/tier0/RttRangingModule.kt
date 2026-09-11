package dev.cyphernova.mobileops.modules.tier0

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.net.wifi.ScanResult
import android.net.wifi.rtt.RangingRequest
import android.net.wifi.rtt.RangingResult
import android.net.wifi.rtt.RangingResultCallback
import android.net.wifi.rtt.WifiRttManager
import android.os.Build
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
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.concurrent.Executors
import kotlin.coroutines.resume

/**
 * Measures the physical distance to access points using 802.11mc fine timing measurement.
 *
 * RSSI is a terrible distance estimate — it collapses under walls, antenna orientation and
 * transmit power, so "strong signal" and "close" are only loosely related. 802.11mc measures
 * round-trip flight time instead, which gives metres with an error of one to two metres and does
 * not care how loud the AP is.
 *
 * Why that matters off-network: it is how a rogue AP gets located. An unexpected SSID with a
 * randomised BSSID tells you something is there; a distance reading taken from two or three
 * positions tells you where. No association is involved — the exchange is a pair of management
 * frames, and the AP answers anyone who asks.
 *
 * Not every AP supports it. Ranging is opt-in on the AP side, so the module reports which ones
 * responded and which ones were never candidates.
 */
class RttRangingModule : PentestModule {
    override val id = "t0.wifi.rtt"
    override val title = "Distance ranging (802.11mc)"
    override val description =
        "Measures true distance in metres to APs that support fine timing measurement. Needs no " +
            "association — useful for physically locating a rogue AP by triangulating from a few spots."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.ACTIVE
    override val category = ModuleCategory.RADIO
    override val requiredPermissions = listOf(Manifest.permission.ACCESS_FINE_LOCATION)

    @SuppressLint("MissingPermission")
    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            return ModuleOutcome.Blocked("802.11mc ranging needs Android 9 or later.")
        }

        val androidContext = context.androidContext
        if (!androidContext.packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI_RTT)) {
            return ModuleOutcome.Blocked(
                "This handset has no 802.11mc ranging hardware. The capability is in the chipset, " +
                    "not the software, so nothing can work around it.",
            )
        }

        val rtt = androidContext.getSystemService(Context.WIFI_RTT_RANGING_SERVICE) as? WifiRttManager
            ?: return ModuleOutcome.Blocked("The ranging service is unavailable.")
        if (!rtt.isAvailable) {
            return ModuleOutcome.Blocked(
                "Ranging is switched off. It follows the WiFi and location toggles — both must be on.",
            )
        }

        val radio = WifiRadio(androidContext)
        if (!radio.isWifiEnabled) {
            return ModuleOutcome.Blocked("WiFi must be on to range, even though nothing is joined.")
        }

        radio.requestScan()
        delay(SCAN_SETTLE_MS)

        val scans = radio.latestRawResults()
        if (scans.isEmpty()) {
            return ModuleOutcome.Failed("No APs in range to measure against.")
        }

        val responders = scans.filter { it.is80211mcResponder }
        if (responders.isEmpty()) {
            emit(noRespondersFinding(scans.size))
            return ModuleOutcome.Completed(
                "${scans.size} AP(s) heard, none support 802.11mc ranging.",
            )
        }

        // A ranging request has a hard peer limit — the burst has to fit in one measurement
        // window — so the strongest candidates go first.
        val limit = RangingRequest.getMaxPeers()
        val chosen = responders.sortedByDescending { it.level }.take(limit)

        val results = range(rtt, chosen)
            ?: return ModuleOutcome.Failed(
                "The ranging burst was rejected. This usually means another app is ranging, or " +
                    "the radio is busy associating.",
            )

        val successful = results.filter { it.status == RangingResult.STATUS_SUCCESS }
        successful.forEach { result -> emit(rangeFinding(result, scans)) }

        emit(summaryFinding(scans.size, responders.size, chosen.size, successful.size))

        return ModuleOutcome.Completed(
            "${successful.size} of ${chosen.size} AP(s) ranged; ${responders.size} of ${scans.size} " +
                "support it.",
        )
    }

    /**
     * The platform's ranging API is callback-based and answers on an executor of the caller's
     * choosing, so it is bridged to a suspension here rather than leaking a thread.
     */
    @SuppressLint("MissingPermission")
    private suspend fun range(
        rtt: WifiRttManager,
        peers: List<ScanResult>,
    ): List<RangingResult>? = suspendCancellableCoroutine { continuation ->
        val executor = Executors.newSingleThreadExecutor()
        val callback = object : RangingResultCallback() {
            override fun onRangingFailure(code: Int) {
                if (continuation.isActive) continuation.resume(null)
            }

            override fun onRangingResults(results: MutableList<RangingResult>) {
                if (continuation.isActive) continuation.resume(results.toList())
            }
        }

        continuation.invokeOnCancellation { executor.shutdownNow() }

        val request = runCatching {
            RangingRequest.Builder().addAccessPoints(peers).build()
        }.getOrNull()

        if (request == null) {
            if (continuation.isActive) continuation.resume(null)
            return@suspendCancellableCoroutine
        }

        val started = runCatching { rtt.startRanging(request, executor, callback) }
        if (started.isFailure && continuation.isActive) continuation.resume(null)
    }

    private fun rangeFinding(result: RangingResult, scans: List<ScanResult>): Finding {
        val mac = result.macAddress?.toString().orEmpty()
        val scan = scans.firstOrNull { it.BSSID.equals(mac, ignoreCase = true) }
        val ssid = scan?.SSID?.takeIf { it.isNotBlank() } ?: "<hidden>"
        val metres = result.distanceMm / 1000.0
        val error = result.distanceStdDevMm / 1000.0

        return Finding(
            moduleId = id,
            observedAtEpochMs = System.currentTimeMillis(),
            severity = Severity.INFO,
            title = "Ranged $ssid at ${"%.1f".format(metres)} m",
            subject = mac,
            detail = buildString {
                append("${"%.2f".format(metres)} m")
                if (error > 0) append(" ±${"%.2f".format(error)} m")
                append(", from ${result.numSuccessfulMeasurements} of ")
                append("${result.numAttemptedMeasurements} measurement(s) at ${result.rssi} dBm. ")
                append(OuiLookup.describe(mac))
                append(". Take a second reading from a different position: two distances put the ")
                append("AP on a circle each, and the intersection is where it physically is.")
            },
            data = mapOf(
                "bssid" to mac,
                "ssid" to ssid,
                "distance_m" to "%.2f".format(metres),
                "stddev_m" to "%.2f".format(error),
                "rssi" to result.rssi.toString(),
                "measurements_ok" to result.numSuccessfulMeasurements.toString(),
                "measurements_attempted" to result.numAttemptedMeasurements.toString(),
            ),
        )
    }

    private fun noRespondersFinding(heard: Int) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.INFO,
        title = "No 802.11mc responders in range",
        subject = "RF environment",
        detail = "This handset can range, but none of the $heard AP(s) heard advertise fine " +
            "timing measurement support. That is normal for consumer equipment — the feature is " +
            "mostly found in enterprise APs and newer mesh systems.",
        data = mapOf("aps_heard" to heard.toString(), "responders" to "0"),
    )

    private fun summaryFinding(heard: Int, responders: Int, attempted: Int, ranged: Int) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.INFO,
        title = "Ranging: $ranged AP(s) measured",
        subject = "RF environment",
        detail = "$responders of $heard AP(s) in range support 802.11mc; $attempted were measured " +
            "in this burst and $ranged returned a distance. An AP that answers a ranging request " +
            "from an unassociated device is disclosing its position to anyone in range, which is " +
            "worth noting where physical concealment was part of the design.",
        data = mapOf(
            "aps_heard" to heard.toString(),
            "responders" to responders.toString(),
            "attempted" to attempted.toString(),
            "ranged" to ranged.toString(),
        ),
    )

    private companion object {
        const val SCAN_SETTLE_MS = 4_000L
    }
}
