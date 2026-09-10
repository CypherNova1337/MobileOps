package dev.cyphernova.mobileops.modules.tier0

import android.annotation.SuppressLint
import android.content.Context
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager

/** A scan result flattened into the fields the modules actually reason about. */
data class ApObservation(
    val ssid: String,
    val bssid: String,
    val capabilities: String,
    val frequencyMhz: Int,
    val rssiDbm: Int,
) {
    val isHidden: Boolean get() = ssid.isBlank()
    val displaySsid: String get() = if (isHidden) "<hidden>" else ssid
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

    /**
     * Asks the platform for a fresh scan. Returns false when the request was throttled — the
     * caller should fall back to [latestResults] rather than treat it as a failure.
     */
    @SuppressLint("MissingPermission")
    fun requestScan(): Boolean = runCatching { wifiManager.startScan() }.getOrDefault(false)

    @SuppressLint("MissingPermission")
    @Suppress("DEPRECATION")
    fun latestResults(): List<ApObservation> =
        runCatching {
            wifiManager.scanResults.map { result: ScanResult ->
                ApObservation(
                    ssid = result.SSID.orEmpty(),
                    bssid = result.BSSID.orEmpty(),
                    capabilities = result.capabilities.orEmpty(),
                    frequencyMhz = result.frequency,
                    rssiDbm = result.level,
                )
            }
        }.getOrDefault(emptyList())
}
