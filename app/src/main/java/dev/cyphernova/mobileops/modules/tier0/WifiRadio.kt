package dev.cyphernova.mobileops.modules.tier0

import android.annotation.SuppressLint
import android.content.Context
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import android.os.Build

/** A scan result flattened into the fields the modules actually reason about. */
data class ApObservation(
    val ssid: String,
    val bssid: String,
    val capabilities: String,
    val frequencyMhz: Int,
    val rssiDbm: Int,
    /** Raw beacon elements as (id, payload); empty below API 30, where they are unavailable. */
    val informationElements: List<Pair<Int, ByteArray>> = emptyList(),
) {
    val isHidden: Boolean get() = ssid.isBlank()
    val displaySsid: String get() = if (isHidden) "<hidden>" else ssid
    /**
     * 0 dBm would be a full milliwatt arriving at the antenna, which does not happen. The
     * platform uses it as "withheld", so it is treated as absent rather than reported as a
     * reading.
     */
    val hasRssi: Boolean get() = rssiDbm != 0

    val rssiLabel: String get() = if (hasRssi) "$rssiDbm dBm" else "signal withheld"

    val band: String
        get() = when (frequencyMhz) {
            in 2401..2495 -> "2.4 GHz"
            in 5150..5895 -> "5 GHz"
            in 5925..7125 -> "6 GHz"
            else -> "$frequencyMhz MHz"
        }

    /** The 24-bit vendor prefix — the part of a BSSID that identifies the hardware maker. */
    val oui: String get() = bssid.replace(":", "").uppercase().take(6)

    val channel: Int
        get() = when (frequencyMhz) {
            2484 -> 14
            in 2412..2472 -> (frequencyMhz - 2407) / 5
            in 5160..5895 -> (frequencyMhz - 5000) / 5
            in 5955..7115 -> (frequencyMhz - 5950) / 5
            else -> -1
        }
}

/**
 * Thin wrapper over [WifiManager] that hands back the last scan the platform is willing to
 * share. Deliberately does not call `startScan()` on every read: since Android 10 a foreground
 * app gets four scans per two-minute window, and burning that budget just returns cached
 * results anyway.
 */
class WifiRadio(context: Context) {

    private val wifiManager =
        context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager

    val isWifiEnabled: Boolean get() = wifiManager.isWifiEnabled

    /** True where the platform will hand over raw beacon elements rather than a summary string. */
    val elementsAvailable: Boolean get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R

    /**
     * Raw information elements, added to [ScanResult] in API 30. Everything below that is stuck
     * with the summarised capability string, so the richer findings simply do not appear.
     */
    private fun elementsOf(result: ScanResult): List<Pair<Int, ByteArray>> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return emptyList()
        return runCatching {
            result.informationElements.orEmpty().mapNotNull { element ->
                val buffer = element.bytes ?: return@mapNotNull null
                val payload = ByteArray(buffer.remaining())
                buffer.duplicate().get(payload)
                element.id to payload
            }
        }.getOrDefault(emptyList())
    }

    /**
     * Asks the platform for a fresh scan. Returns false when the request was throttled — the
     * caller should fall back to [latestResults] rather than treat it as a failure.
     */
    @SuppressLint("MissingPermission")
    fun requestScan(): Boolean = runCatching { wifiManager.startScan() }.getOrDefault(false)

    /**
     * The platform's own scan objects, unflattened.
     *
     * Ranging is the one caller that needs these: `RangingRequest` takes [ScanResult] instances
     * and reads fields off them that [ApObservation] does not carry, so handing it a rebuilt
     * object would not work.
     */
    @SuppressLint("MissingPermission")
    fun latestRawResults(): List<ScanResult> =
        runCatching { wifiManager.scanResults.orEmpty() }.getOrDefault(emptyList())

    @SuppressLint("MissingPermission")
    @Suppress("DEPRECATION")
    fun latestResults(): List<ApObservation> =
        runCatching {
            // The AP we are associated with reports a live RSSI through WifiInfo even when the
            // scan entry does not, so it can be repaired where it matters most.
            val connected = runCatching { wifiManager.connectionInfo }.getOrNull()
            val connectedBssid = connected?.bssid
            val connectedRssi = connected?.rssi ?: 0

            wifiManager.scanResults.map { result: ScanResult ->
                val level = result.level
                val repaired = if (
                    level == 0 &&
                    connectedRssi != 0 &&
                    connectedBssid != null &&
                    connectedBssid.equals(result.BSSID, ignoreCase = true)
                ) {
                    connectedRssi
                } else {
                    level
                }

                ApObservation(
                    ssid = result.SSID.orEmpty(),
                    bssid = result.BSSID.orEmpty(),
                    capabilities = result.capabilities.orEmpty(),
                    frequencyMhz = result.frequency,
                    rssiDbm = repaired,
                    informationElements = elementsOf(result),
                )
            }
        }.getOrDefault(emptyList())
}
