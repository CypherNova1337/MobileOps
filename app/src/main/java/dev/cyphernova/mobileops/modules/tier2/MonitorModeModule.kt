package dev.cyphernova.mobileops.modules.tier2

import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleCategory
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule
import dev.cyphernova.mobileops.modules.tier1.RootShell

/**
 * Verifies that a radio really can enter monitor mode, and reports which channels it will
 * accept. This is the gate the rest of Tier 2 sits behind: 802.11 frame analysis is only
 * meaningful once the driver has actually confirmed monitor support.
 *
 * Deliberately scoped to capture. Frame *injection* — deauthentication in particular — is a
 * denial-of-service primitive against everyone on the channel, not just the target, so it is
 * not implemented here.
 */
class MonitorModeModule : PentestModule {
    override val id = "t2.radio.monitor"
    override val title = "Monitor mode capability check"
    override val description =
        "Confirms whether a radio will enter monitor mode and enumerates the channels the driver reports. " +
            "Capture-oriented: frame injection is out of scope."
    override val requiredTier = Tier.T2_MONITOR
    override val intrusiveness = Intrusiveness.PASSIVE
    override val category = ModuleCategory.PRIVILEGED

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        // Report the adapter before anything else: an unclaimed adapter is the usual reason this
        // module cannot run, and "no iw binary" would be a misleading thing to say about it.
        context.capabilities.usbAdapters.forEach { adapter ->
            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    severity = if (adapter.claimedByKernel) Severity.INFO else Severity.LOW,
                    title = "${adapter.chipset} on USB (${adapter.identifier})",
                    subject = adapter.identifier,
                    detail = buildString {
                        append(adapter.productName?.let { "$it. " } ?: "")
                        append(
                            if (adapter.claimedByKernel) {
                                "Claimed by the kernel via ${adapter.driver}. "
                            } else {
                                "Present on the bus but unclaimed — no ${adapter.driver} in this kernel. "
                            },
                        )
                        append(
                            if (adapter.monitorCapable) {
                                "This chipset supports monitor mode" +
                                    if (adapter.injectionCapable) " and injection." else "."
                            } else {
                                "This chipset does not support monitor mode."
                            },
                        )
                        adapter.blockers(context.capabilities.rooted).forEach { append(" $it") }
                    },
                    data = mapOf(
                        "usb_id" to adapter.identifier,
                        "chipset" to adapter.chipset,
                        "driver" to adapter.driver,
                        "firmware" to adapter.firmware.orEmpty(),
                        "claimed" to adapter.claimedByKernel.toString(),
                    ),
                ),
            )
        }

        val iw = RootShell.which("iw")
            ?: return ModuleOutcome.Blocked(
                "No `iw` binary. Monitor mode configuration needs iw (or a NetHunter-style toolchain).",
            )

        val candidates = context.capabilities.externalAdapters.ifEmpty {
            context.capabilities.wifiInterfaces
        }
        if (candidates.isEmpty()) {
            return ModuleOutcome.Failed("No WiFi interfaces visible under /sys/class/net.")
        }

        var capable = 0

        candidates.forEach { iface ->
            val info = RootShell.exec("$iw phy 2>/dev/null | grep -A 20 'Supported interface modes'")
            val supportsMonitor = info.stdout.contains("monitor", ignoreCase = true)
            val channels = RootShell.exec("$iw phy 2>/dev/null | grep -c 'MHz'").stdout.trim()

            if (supportsMonitor) capable++

            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    severity = if (supportsMonitor) Severity.INFO else Severity.LOW,
                    title = if (supportsMonitor) {
                        "$iface supports monitor mode"
                    } else {
                        "$iface does not advertise monitor mode"
                    },
                    subject = iface,
                    detail = if (supportsMonitor) {
                        "The driver lists monitor among its supported interface modes; " +
                            "$channels frequency entries reported."
                    } else {
                        "The driver does not list monitor mode. On an internal Broadcom radio this usually " +
                            "means the firmware is unpatched; an external adapter with an ath9k_htc or " +
                            "rtl8812au driver is the reliable route."
                    },
                    data = mapOf(
                        "interface" to iface,
                        "monitor_supported" to supportsMonitor.toString(),
                        "frequency_entries" to channels,
                    ),
                ),
            )
        }

        return ModuleOutcome.Completed("$capable of ${candidates.size} interface(s) support monitor mode.")
    }
}
