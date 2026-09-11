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

            val ipp = queryIpp(host)
            if (ipp.attributes != null) {
                spokeToThis = true
                emit(ippFinding(host, ipp.attributes))
            } else if (ipp.attempts.isNotEmpty()) {
                // 631 being open and IPP returning nothing is a fact worth recording. Silence
                // here is indistinguishable from the module not having looked.
                emit(ippSilentFinding(host, ipp.attempts))
            }

            val pjl = queryPjl(host)
            if (pjl.blocks.isNotEmpty()) {
                spokeToThis = true
                val model = Pjl.modelIn(pjl.blocks)
                val settings = Pjl.settingsIn(pjl.blocks)
                val files = Pjl.filesIn(pjl.blocks)

                emit(pjlFinding(host, model, settings, files))

                val concerns = Pjl.concerns(settings)
                if (concerns.isNotEmpty()) emit(settingsFinding(host, concerns))
                if (files.isNotEmpty()) emit(storageFinding(host, files))
            } else if (pjl.stoppedAt != null) {
                emit(pjlSilentFinding(host, pjl.stoppedAt))
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

    /** What the IPP query got, including the reasons it got nothing. */
    private data class IppResult(
        val attributes: Ipp.Attributes? = null,
        val attempts: List<String> = emptyList(),
    )

    private suspend fun queryIpp(host: String): IppResult {
        val attempts = mutableListOf<String>()
        // Devices serve one of these paths, not all of them, and which one is not predictable
        // from the model — so each is tried and each outcome recorded.
        IPP_PATHS.forEach { path ->
            val url = "http://$host:$IPP_PORT$path"
            val attempt = LanHttpClient.attempt(
                url = url,
                method = "POST",
                timeoutMs = REQUEST_TIMEOUT_MS,
                body = Ipp.getPrinterAttributesRequest("ipp://$host:$IPP_PORT$path"),
                headers = mapOf("Content-Type" to "application/ipp"),
            )
            val response = (attempt as? LanHttpClient.Attempt.Answered)?.response
            if (response == null) {
                attempts += attempt.describe()
                return@forEach
            }
            // The body is binary and came back through a client that decoded it as Latin-1,
            // which round-trips every byte.
            val attributes = Ipp.parse(response.body.toByteArray(Charsets.ISO_8859_1))
            when {
                attributes == null ->
                    attempts += "$url — HTTP ${response.status}, " +
                        "${response.body.length} bytes that did not decode as IPP"
                !attributes.isSuccess ->
                    attempts += "$url — IPP status 0x%04x".format(attributes.statusCode)
                attributes.values.isEmpty() ->
                    attempts += "$url — IPP answered with no attributes"
                else -> return IppResult(attributes, attempts + "$url — answered")
            }
        }
        return IppResult(null, attempts)
    }

    /** What the PJL query got, and why it got nothing when it did. */
    private data class PjlResult(
        val blocks: List<Pjl.Block> = emptyList(),
        val stoppedAt: String? = null,
    )

    private suspend fun queryPjl(host: String): PjlResult = withContext(Dispatchers.IO) {
        var stoppedAt: String? = null
        val blocks = runCatching {
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
                if (total == 0) {
                    stoppedAt = "connected to 9100 and the printer sent nothing back"
                    return@use emptyList()
                }
                val parsed = Pjl.parse(String(buffer, 0, total, Charsets.ISO_8859_1))
                if (parsed.isEmpty()) {
                    stoppedAt = "$total bytes came back that did not parse as PJL"
                }
                parsed
            }
        }.getOrElse { failure ->
            // Same discipline as the IPP path: a refused port, a timeout and a reply that did not
            // parse are three different next steps, and silence is none of them.
            stoppedAt = failure.message ?: failure.javaClass.simpleName
            emptyList()
        }
        PjlResult(blocks, stoppedAt)
    }

    // ---- Findings ------------------------------------------------------------------------------

    private fun pjlSilentFinding(host: String, stoppedAt: String) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.INFO,
        title = "PJL did not answer on $host",
        subject = host,
        detail = "Port 9100 was asked for the device inventory and gave nothing usable: " +
            stoppedAt + ". A printer that refuses the connection is not serving a job socket; " +
            "one that accepts it and stays silent has PJL disabled or is waiting for print data " +
            "rather than commands. Either is worth knowing — it is the difference between a " +
            "hardened device and one that was never asked.",
        data = mapOf("host" to host, "stopped_at" to stoppedAt),
    )

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

    private fun ippSilentFinding(host: String, attempts: List<String>) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.INFO,
        title = "IPP did not answer on $host",
        subject = host,
        detail = "Get-Printer-Attributes was sent and no usable reply came back. What each " +
            "attempt did: " + attempts.joinToString("; ") + ". A refused connection means 631 " +
            "is not serving IPP; an HTTP status with a body that did not decode means the path " +
            "is wrong for this model; an IPP error status means the device answered and " +
            "declined. Any of those is worth a look by hand before concluding the printer is " +
            "reticent.",
        data = mapOf("host" to host, "attempted" to attempts.joinToString("; ")),
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

    /**
     * Settings that change what to do next, and what each value means.
     *
     * Severity follows the concern rather than the keyword: a printer naming a mail server holds
     * someone else's account, which is a different finding from a printer whose own password
     * feature is switched off.
     */
    private fun settingsFinding(host: String, concerns: List<Pjl.Note>) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = if (concerns.any { it.concern == Pjl.Concern.REACHES_SERVER }) {
            Severity.HIGH
        } else {
            Severity.MEDIUM
        },
        title = "Printer configuration readable without credentials — $host",
        subject = host,
        detail = "Read by a caller presenting nothing: " +
            concerns.joinToString("; ") { "${it.key}=${it.value} — ${it.meaning}" } + ".",
        data = mapOf(
            "host" to host,
            "concerns" to concerns.joinToString { it.concern.name },
        ) + concerns.associate { "pjl_${it.key.lowercase()}" to it.value },
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
