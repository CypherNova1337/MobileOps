package dev.cyphernova.mobileops.modules.tier0

import android.net.VpnService
import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.capture.CaptureController
import dev.cyphernova.mobileops.core.capture.CaptureVpnService
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule
import kotlinx.coroutines.delay
import java.io.File

/**
 * Starts and stops the no-root packet capture. Running the module toggles it, so the same
 * control starts a capture and closes it out with a finding naming the pcap.
 */
class VpnCaptureModule : PentestModule {
    override val id = "t0.capture.vpn"
    override val title = "Traffic capture (no root)"
    override val description =
        "Routes this device's traffic through a local TUN interface and writes every packet to a pcap. " +
            "Needs no root — the VPN permission prompt is the only gate. Run again to stop."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.PASSIVE

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val androidContext = context.androidContext

        if (CaptureController.isRunning) {
            val status = CaptureController.status.value
            CaptureVpnService.stop(androidContext)
            delay(TEARDOWN_GRACE_MS)

            val pcap = status.pcapPath?.let(::File)
            val duration = (System.currentTimeMillis() - status.startedAtEpochMs) / 1000

            // A quiet capture is ambiguous — idle device, or every flow failing. The counters
            // settle it, so the verdict rides on the finding rather than the packet count.
            val healthy = status.diagnosis.startsWith("Relay healthy")

            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    severity = if (healthy) Severity.INFO else Severity.MEDIUM,
                    title = "Capture stopped — ${status.packets} packets",
                    subject = pcap?.name ?: "capture",
                    detail = "${status.packets} packets (${status.bytes / 1024} KiB) over ${duration}s " +
                        "written to ${pcap?.absolutePath ?: "the capture directory"}. " +
                        "Open it in Wireshark; the link type is RAW.\n\n" +
                        "Relay: ${status.diagnosis}",
                    data = buildMap {
                        put("path", status.pcapPath ?: "")
                        put("packets", status.packets.toString())
                        put("bytes", status.bytes.toString())
                        put("duration_s", duration.toString())
                        status.counters.forEach { (key, value) -> put(key, value.toString()) }
                    },
                ),
            )
            return ModuleOutcome.Completed("${status.packets} packets. ${status.diagnosis}")
        }

        // The system consent dialog can only be raised from an Activity, so the UI handles it
        // and this reports the state rather than trying to prompt from here.
        if (VpnService.prepare(androidContext) != null) {
            return ModuleOutcome.Blocked(
                "VPN permission not granted. Tap 'Grant VPN permission' on this card, then run again.",
            )
        }

        CaptureVpnService.start(androidContext)
        delay(STARTUP_GRACE_MS)

        if (!CaptureController.isRunning) {
            val error = CaptureController.status.value.error
            return ModuleOutcome.Failed(error ?: "The capture service did not start.")
        }

        emit(
            Finding(
                moduleId = id,
                observedAtEpochMs = System.currentTimeMillis(),
                severity = Severity.INFO,
                title = "Capture started",
                subject = CaptureController.status.value.pcapPath.orEmpty(),
                detail = "All device traffic is now routed through the local TUN and written to disk. " +
                    "Run this module again to stop and close the file.",
            ),
        )
        return ModuleOutcome.Completed("Capture running — run again to stop.")
    }

    private companion object {
        const val STARTUP_GRACE_MS = 900L
        const val TEARDOWN_GRACE_MS = 400L
    }
}
