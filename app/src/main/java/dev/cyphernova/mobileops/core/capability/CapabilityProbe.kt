package dev.cyphernova.mobileops.core.capability

import android.content.Context
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File

/**
 * Observes the device rather than trusting build flags: probes for a usable root shell, walks
 * the kernel's network interfaces looking for a second WiFi radio, and reports the honest
 * ceiling on what modules can run here.
 */
class CapabilityProbe(private val context: Context) {

    suspend fun probe(): DeviceCapabilities = withContext(Dispatchers.IO) {
        val (rooted, rootDetail) = probeRoot()
        val interfaces = wifiInterfaces()
        val external = interfaces.filter { it != PRIMARY_WLAN }
        val (monitor, monitorDetail) = probeMonitorMode(rooted, external)

        DeviceCapabilities(
            sdkInt = Build.VERSION.SDK_INT,
            deviceLabel = "${Build.MANUFACTURER} ${Build.MODEL} (API ${Build.VERSION.SDK_INT})",
            rooted = rooted,
            rootDetail = rootDetail,
            wifiInterfaces = interfaces,
            externalAdapters = external,
            monitorModeAvailable = monitor,
            monitorModeDetail = monitorDetail,
            scanThrottled = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q,
            locationPermissionRequired = true,
        )
    }

    /**
     * A root check that actually asks for a shell instead of stat-ing `su` and hoping. Binary
     * presence is necessary but nowhere near sufficient — plenty of ROMs ship a stub `su` that
     * denies every request, and the difference matters before a module tries to run tcpdump.
     */
    private suspend fun probeRoot(): Pair<Boolean, String> {
        val binary = SU_PATHS.firstOrNull { File(it).exists() }
            ?: return false to "no su binary on any known path"

        val granted = withTimeoutOrNull(ROOT_PROBE_TIMEOUT_MS) {
            runCatching {
                val process = ProcessBuilder(binary, "-c", "id -u")
                    .redirectErrorStream(true)
                    .start()
                val output = process.inputStream.bufferedReader().use { it.readText() }.trim()
                process.waitFor()
                output.lineSequence().lastOrNull()?.trim() == "0"
            }.getOrDefault(false)
        }

        return when (granted) {
            true -> true to "root granted via $binary"
            false -> false to "$binary present but the shell request was denied"
            // Timed out: almost always a superuser prompt the user has not answered.
            null -> false to "$binary present, request timed out (grant the prompt and re-probe)"
        }
    }

    /** WiFi-looking interfaces the kernel currently exposes. */
    private fun wifiInterfaces(): List<String> =
        runCatching {
            File("/sys/class/net").listFiles()
                ?.map { it.name }
                ?.filter { name -> WIFI_IFACE_PREFIXES.any { name.startsWith(it) } }
                ?.sorted()
                .orEmpty()
        }.getOrDefault(emptyList())

    /**
     * Monitor mode needs both a radio that supports it and the privilege to reconfigure that
     * radio. On a stock Android 10+ device neither is on offer, so we say so plainly instead
     * of surfacing a module that will fail at run time.
     */
    private fun probeMonitorMode(rooted: Boolean, external: List<String>): Pair<Boolean, String> {
        if (!rooted) {
            return false to "requires root; the platform has not exposed monitor mode to apps since Android 10"
        }
        if (external.isNotEmpty()) {
            return true to "external adapter present: ${external.joinToString()} (driver support still required)"
        }
        // Nexmon-style patches expose their firmware control node under the driver's debugfs dir.
        val nexmon = NEXMON_MARKERS.firstOrNull { File(it).exists() }
        return if (nexmon != null) {
            true to "patched firmware detected at $nexmon"
        } else {
            false to "rooted, but no external adapter and no patched-firmware marker found"
        }
    }

    private companion object {
        const val PRIMARY_WLAN = "wlan0"
        const val ROOT_PROBE_TIMEOUT_MS = 4_000L
        val WIFI_IFACE_PREFIXES = listOf("wlan", "wlp", "wlx")
        val SU_PATHS = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/su/bin/su",
            "/data/adb/su",
            "/debug_ramdisk/su",
        )
        val NEXMON_MARKERS = listOf(
            "/sys/kernel/debug/ieee80211/phy0/nexmon",
            "/data/local/tmp/nexutil",
        )
    }
}
