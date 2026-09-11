package dev.cyphernova.mobileops.modules.tier0

import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.iot.DeviceEvidence
import dev.cyphernova.mobileops.core.iot.DeviceFingerprint
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleCategory
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule
import dev.cyphernova.mobileops.core.printer.Ipp
import dev.cyphernova.mobileops.core.printer.Pjl
import dev.cyphernova.mobileops.core.target.HostHarvest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Asks a printer what it knows about itself.
 *
 * A printer is usually written up as an inventory line, which undersells it. It holds the
 * documents people scanned, the address book they scanned them to, and — where scan-to-folder or
 * scan-to-email is configured — a credential for a file server or a mail server that the printer
 * has to store in a form it can replay. Reaching that credential is a finding about the domain,
 * not about the printer.
 *
 * Two protocols answer without any credential:
 *
 *  - **IPP on 631** answers `Get-Printer-Attributes` to anyone, by design: a client must be able
 *    to discover a printer before submitting to it. Make, model, firmware, location, contact.
 *  - **PJL on 9100** is a raw job socket with no authentication at all, and interprets control
 *    commands alongside print data. It reports the device's settings and, on many models, lists
 *    the files on its own storage.
 *
 * Everything sent here is read-only. PJL can set the panel message, change defaults and delete
 * files; none of that is sent, because an assessment has no business altering the device, and a
 * changed default on a shared printer is an outage someone else has to diagnose.
 */
class PrinterModule : PentestModule {
    override val id = "t0.iot.printer"
    override val title = "Printer disclosure"
    override val description =
        "Queries printers over IPP and PJL without credentials: model, firmware, settings and, " +
            "where the device allows it, a listing of its own storage. Flags stored-job and " +
            "scan-to-folder configuration, which is where a printer holds someone else's " +
            "credentials. Read-only — nothing is printed, altered or deleted."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.ACTIVE
    override val category = ModuleCategory.NETWORK
    override val requiresTarget = false
    override val prerequisites = listOf("t0.net.discovery")

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val printers = targets(context)
        if (printers.isEmpty()) {
            return ModuleOutcome.Completed(
                "No printers found. Run the port scan so 515, 631 or 9100 can be seen.",
            )
        }

        var answered = 0
        printers.forEach { host ->
            var spokeToThis = false

            queryIpp(host)?.let { attributes ->
                spokeToThis = true
                emit(ippFinding(host, attributes))
            }

            queryPjl(host)?.let { blocks ->
                spokeToThis = true
                val model = Pjl.modelIn(blocks)
                val settings = Pjl.settingsIn(blocks)
                val files = Pjl.filesIn(blocks)

                emit(pjlFinding(host, model, settings, files))

                val notable = Pjl.notableSettings(settings)
                if (notable.isNotEmpty()) emit(settingsFinding(host, notable))
                if (files.isNotEmpty()) emit(storageFinding(host, files))
            }

            if (spokeToThis) answered++
        }

        return ModuleOutcome.Completed(
            "Queried ${printers.size} printer(s); $answered answered without credentials.",
        )
    }

    /**
     * Selected hosts, or every host the run already classified as a printer.
     *
     * Classification is pooled from the whole log rather than from a port list, so a device the
     * port scan only saw on 80 and 443 is still recognised when its banner named a Lexmark.
     */
    private fun targets(context: ModuleContext): List<String> {
        val selected = context.targets.hosts()
        if (selected.isNotEmpty()) return selected.distinct()
        val gateway = context.priorFindings
            .firstNotNullOfOrNull { it.data["gateway"]?.trim()?.takeIf { value -> value.isNotBlank() } }
        return HostHarvest.hostsIn(context.priorFindings)
            .map { it.address }
            .filter { address ->
                val evidence = DeviceEvidence.forHost(context.priorFindings, address, gateway)
                DeviceFingerprint.classify(evidence).category == DeviceFingerprint.Category.PRINTER ||
                    evidence.openPorts.any { it in PRINTER_PORTS }
            }
            .distinct()
    }

    private suspend fun queryIpp(host: String): Ipp.Attributes? {
        // Both paths are in wide use and a device serves one or the other, not both.
        IPP_PATHS.forEach { path ->
            val response = LanHttpClient.probe(
                url = "http://$host:$IPP_PORT$path",
                method = "POST",
                timeoutMs = REQUEST_TIMEOUT_MS,
                body = Ipp.getPrinterAttributesRequest("ipp://$host$path"),
                headers = mapOf("Content-Type" to "application/ipp"),
            ) ?: return@forEach
            // The body is binary, and it came back through a client that decoded it as Latin-1,
            // which round-trips every byte.
            val attributes = Ipp.parse(response.body.toByteArray(Charsets.ISO_8859_1))
            if (attributes != null && attributes.isSuccess && attributes.values.isNotEmpty()) {
                return attributes
            }
        }
        return null
    }

    private suspend fun queryPjl(host: String): List<Pjl.Block>? = withContext(Dispatchers.IO) {
        runCatching {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, PJL_PORT), CONNECT_TIMEOUT_MS)
                socket.soTimeout = REQUEST_TIMEOUT_MS
                socket.getOutputStream().apply {
                    write(Pjl.inventoryRequest())
                    flush()
                }
                // A printer answers as it works through the queries and then simply stops rather
                // than closing, so the read runs until it goes quiet rather than until EOF.
                val buffer = ByteArray(MAX_PJL_REPLY)
                var total = 0
                runCatching {
                    while (total < MAX_PJL_REPLY) {
                        val read = socket.getInputStream().read(buffer, total, MAX_PJL_REPLY - total)
                        if (read <= 0) break
                        total += read
                    }
                }
                if (total == 0) return@use null
                Pjl.parse(String(buffer, 0, total, Charsets.ISO_8859_1))
            }
        }.getOrNull()?.takeIf { it.isNotEmpty() }
    }

    // ---- Findings ------------------------------------------------------------------------------

    private fun ippFinding(host: String, attributes: Ipp.Attributes) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = if (attributes.acceptsUnauthenticated) Severity.MEDIUM else Severity.LOW,
        title = "Printer answers IPP without credentials — $host",
        subject = host,
        detail = buildString {
            append("Get-Printer-Attributes was answered by an unauthenticated caller. ")
            attributes.makeAndModel?.let { append("Model '$it'. ") }
            attributes.firmware?.let { append("Firmware '$it'. ") }
            attributes.location?.let { append("Location '$it'. ") }
            attributes.info?.let { append("Described as '$it'. ") }
            attributes.queuedJobs?.let { append("$it job(s) queued. ") }
            if (attributes.acceptsUnauthenticated) {
                append(
                    "It reports uri-authentication-supported as 'none', which is the device " +
                        "stating that it will take a job from anyone who can reach it. ",
                )
            }
            if (attributes.hasCleartextUri) {
                append(
                    "It advertises a cleartext ipp:// URI, so documents and any credential sent " +
                        "with them cross this segment unencrypted — and client isolation is not " +
                        "in effect here.",
                )
            }
        },
        data = mapOf(
            "host" to host,
            "model" to attributes.makeAndModel.orEmpty(),
            "firmware" to attributes.firmware.orEmpty(),
            "location" to attributes.location.orEmpty(),
            "queued_jobs" to (attributes.queuedJobs?.toString() ?: ""),
            "unauthenticated" to attributes.acceptsUnauthenticated.toString(),
        ).filterValues { it.isNotBlank() },
    )

    private fun pjlFinding(
        host: String,
        model: String?,
        settings: Map<String, String>,
        files: List<Pjl.Entry>,
    ) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.MEDIUM,
        title = "Printer accepts PJL commands from anyone — $host",
        subject = host,
        detail = buildString {
            append("Port 9100 is a raw job socket with no authentication, and it answered. ")
            model?.let { append("It identifies itself as '$it'. ") }
            append("${settings.size} setting(s) read")
            if (files.isNotEmpty()) append(" and ${files.size} storage entr(y/ies) listed")
            append(
                ". Only read commands were sent, but the same socket takes the ones that change " +
                    "defaults, overwrite the panel message and delete stored files, and it will " +
                    "take them from any device on this segment.",
            )
        },
        data = mapOf(
            "host" to host,
            "model" to model.orEmpty(),
            "settings_read" to settings.size.toString(),
            "storage_entries" to files.size.toString(),
        ).filterValues { it.isNotBlank() },
    )

    private fun settingsFinding(host: String, notable: Map<String, String>) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.HIGH,
        title = "Printer discloses its security configuration — $host",
        subject = host,
        detail = "Read without credentials: " +
            notable.entries.joinToString("; ") { "${it.key}=${it.value}" } +
            ". Settings named for passwords, directory or mail servers, job storage and disk " +
            "encryption are the ones that decide whether this device holds a credential for " +
            "something else. Where scan-to-folder or scan-to-email is configured, the printer " +
            "must store an account it can replay, and that account is usually on the file server " +
            "or the mail system rather than on the printer.",
        data = mapOf("host" to host) +
            notable.mapKeys { "pjl_${it.key.lowercase()}" },
    )

    private fun storageFinding(host: String, files: List<Pjl.Entry>) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.HIGH,
        title = "Printer storage listed without credentials — $host",
        subject = host,
        detail = buildString {
            append("${files.size} entr(y/ies) on the printer's own filesystem, readable by any ")
            append("caller on this segment: ")
            append(
                files.take(STORAGE_LISTED).joinToString("; ") { entry ->
                    entry.name + if (entry.isDirectory) "/" else {
                        entry.sizeBytes?.let { " (${it} bytes)" }.orEmpty()
                    }
                },
            )
            if (files.size > STORAGE_LISTED) append("; and ${files.size - STORAGE_LISTED} more")
            append(
                ". Held print jobs and scanned documents live here on models that support them, " +
                    "and the same command set that listed this can read the contents.",
            )
        },
        data = mapOf(
            "host" to host,
            "entries" to files.size.toString(),
            "names" to files.take(STORAGE_LISTED).joinToString { it.name },
        ),
    )

    private companion object {
        const val IPP_PORT = 631
        const val PJL_PORT = 9100
        val IPP_PATHS = listOf("/ipp/print", "/")
        val PRINTER_PORTS = setOf(515, 631, 9100)

        const val CONNECT_TIMEOUT_MS = 3_000
        const val REQUEST_TIMEOUT_MS = 6_000

        /** A device inventory is a few kilobytes; a reply far past that is not one. */
        const val MAX_PJL_REPLY = 128 * 1024

        /** Enough names to make the point without printing a whole filesystem into the report. */
        const val STORAGE_LISTED = 20
    }
}
