package dev.cyphernova.mobileops.modules.tier1

import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule
import java.io.File

/**
 * Captures traffic on a live interface to a pcap, using a root shell and whichever tcpdump the
 * device has. Managed-mode capture, so this sees this device's own traffic plus any broadcast
 * and multicast on the segment — not other stations' unicast frames. That needs Tier 2.
 */
class InterfaceCaptureModule(
    private val durationSeconds: Int = 30,
    private val interfaceName: String = "wlan0",
) : PentestModule {
    override val id = "t1.capture.pcap"
    override val title = "Interface packet capture"
    override val description =
        "Runs tcpdump on a live interface via root and writes a timestamped pcap for offline analysis. " +
            "Managed mode: own traffic plus broadcast/multicast only."
    override val requiredTier = Tier.T1_ROOT
    override val intrusiveness = Intrusiveness.PASSIVE

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val tcpdump = RootShell.which("tcpdump")
            ?: return ModuleOutcome.Blocked(
                "No tcpdump on the device. Push an ARM build to /data/local/tmp/tcpdump and chmod +x it.",
            )

        val outputDir = File(context.androidContext.filesDir, "captures").apply { mkdirs() }
        val outputFile = File(outputDir, "capture-${System.currentTimeMillis()}.pcap")

        // -U flushes each packet so a capture cut short is still a readable pcap.
        val command = "$tcpdump -i $interfaceName -s 0 -U -w ${outputFile.absolutePath} " +
            "-G $durationSeconds -W 1 2>&1"
        val result = RootShell.exec(command, timeoutMs = (durationSeconds + 10) * 1_000L)

        if (!outputFile.exists() || outputFile.length() == 0L) {
            return ModuleOutcome.Failed(
                "tcpdump produced no capture. ${result.stdout.take(200).ifBlank { "No output." }}",
            )
        }

        // The file is owned by root after the capture; hand it back so the app can read it.
        RootShell.exec("chmod 644 ${outputFile.absolutePath}", timeoutMs = 5_000)

        emit(
            Finding(
                moduleId = id,
                
                observedAtEpochMs = System.currentTimeMillis(),
                severity = Severity.INFO,
                title = "Capture written (${outputFile.length() / 1024} KiB)",
                subject = interfaceName,
                detail = "${durationSeconds}s of traffic on $interfaceName captured to ${outputFile.name}.",
                data = mapOf(
                    "path" to outputFile.absolutePath,
                    "bytes" to outputFile.length().toString(),
                    "interface" to interfaceName,
                ),
            ),
        )

        return ModuleOutcome.Completed("Captured ${outputFile.length() / 1024} KiB to ${outputFile.name}.")
    }
}
