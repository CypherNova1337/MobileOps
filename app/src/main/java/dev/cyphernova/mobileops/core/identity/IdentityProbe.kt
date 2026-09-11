package dev.cyphernova.mobileops.core.identity

import android.annotation.SuppressLint
import android.content.Context
import android.net.wifi.WifiManager
import android.os.Build
import android.provider.Settings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.net.NetworkInterface

/** What the network can currently learn about this device, and what we are able to change. */
data class IdentitySurface(
    val deviceName: String?,
    val reportedMac: String?,
    val realMacReadable: Boolean,
    val realMac: String?,
    val platformRandomisesMac: Boolean,
    val notes: List<String>,
)

/**
 * Establishes what this device actually exposes, rather than what we would like to believe.
 *
 * Android has spent several releases deliberately closing exactly the holes this would use:
 * since Android 6 an app reading its own WiFi MAC gets the constant `02:00:00:00:00:00`; since
 * Android 10 the real address under `/sys/class/net` is behind SELinux, and the MAC on the air
 * is randomised per network anyway. Those restrictions apply to us as much as to anyone, which
 * is why real spoofing here is a Tier 1 capability.
 */
object IdentityProbe {

    /** The placeholder the platform hands any app that asks for its own MAC. */
    const val REDACTED_MAC = "02:00:00:00:00:00"

    @SuppressLint("HardwareIds", "MissingPermission")
    suspend fun probe(context: Context, rooted: Boolean): IdentitySurface = withContext(Dispatchers.IO) {
        val deviceName = runCatching {
            Settings.Global.getString(context.contentResolver, Settings.Global.DEVICE_NAME)
        }.getOrNull()

        val wifiManager = context.applicationContext
            .getSystemService(Context.WIFI_SERVICE) as? WifiManager

        @Suppress("DEPRECATION")
        val reported = runCatching { wifiManager?.connectionInfo?.macAddress }.getOrNull()

        val real = readRealMac()
        val notes = buildList {
            if (reported == null || reported == REDACTED_MAC) {
                add(
                    "The platform reports this device's WiFi MAC as $REDACTED_MAC. That is a " +
                        "deliberate placeholder, not the real address — apps have not been able to " +
                        "read it since Android 6.",
                )
            }
            if (real == null) {
                add(
                    "The real address under /sys/class/net is unreadable without root, which is " +
                        "the expected result on Android 10 and later.",
                )
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                add(
                    "Android randomises the MAC per saved network by default, so the address this " +
                        "device presents is already not its hardware address. It is stable per " +
                        "network, so it still correlates across sessions on the same SSID.",
                )
            }
            deviceName?.takeIf { it.isNotBlank() }?.let {
                add(
                    "The device name '$it' is sent as the DHCP hostname, so it appears in the " +
                        "network's lease table regardless of MAC randomisation. This is the most " +
                        "commonly overlooked identifier.",
                )
            }
        }

        IdentitySurface(
            deviceName = deviceName,
            reportedMac = reported,
            realMacReadable = real != null,
            realMac = real,
            platformRandomisesMac = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q,
            notes = notes,
        )
    }

    /**
     * Reads the hardware address directly. Works with root, and on older releases; on a modern
     * stock device both routes are closed and this returns null, which is the honest answer.
     */
    private fun readRealMac(): String? {
        val fromSysfs = runCatching {
            File("/sys/class/net/wlan0/address").takeIf { it.canRead() }?.readText()?.trim()
        }.getOrNull()
        if (!fromSysfs.isNullOrBlank() && fromSysfs != REDACTED_MAC) return fromSysfs.uppercase()

        return runCatching {
            NetworkInterface.getNetworkInterfaces().toList()
                .firstOrNull { it.name.equals("wlan0", ignoreCase = true) }
                ?.hardwareAddress
                ?.joinToString(":") { "%02X".format(it) }
        }.getOrNull()
    }
}
