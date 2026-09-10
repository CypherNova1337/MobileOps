package dev.cyphernova.mobileops.core.capability

/**
 * A snapshot of what this specific handset will actually let us do, resolved once at startup
 * and refreshable on demand. Every field is observed, never assumed.
 */
data class DeviceCapabilities(
    val sdkInt: Int,
    val deviceLabel: String,
    val rooted: Boolean,
    val rootDetail: String,
    val wifiInterfaces: List<String>,
    val externalAdapters: List<String>,
    val usbAdapters: List<UsbWifiAdapter>,
    val monitorModeAvailable: Boolean,
    val monitorModeDetail: String,
    val scanThrottled: Boolean,
    val locationPermissionRequired: Boolean,
) {
    /** The highest tier this device can service. */
    val tier: Tier
        get() = when {
            monitorModeAvailable -> Tier.T2_MONITOR
            rooted -> Tier.T1_ROOT
            else -> Tier.T0_STOCK
        }

    /**
     * Android 10 (API 29) throttles foreground apps to 4 [android.net.wifi.WifiManager.startScan]
     * calls per 2-minute window. Surveys have to pace themselves or silently get stale results.
     */
    val scanBudgetPerWindow: Int get() = if (scanThrottled) 4 else Int.MAX_VALUE

    companion object {
        /** Conservative placeholder used before the first probe completes. */
        val UNKNOWN = DeviceCapabilities(
            sdkInt = 0,
            deviceLabel = "probing…",
            rooted = false,
            rootDetail = "not yet probed",
            wifiInterfaces = emptyList(),
            externalAdapters = emptyList(),
            usbAdapters = emptyList(),
            monitorModeAvailable = false,
            monitorModeDetail = "not yet probed",
            scanThrottled = true,
            locationPermissionRequired = true,
        )
    }
}
