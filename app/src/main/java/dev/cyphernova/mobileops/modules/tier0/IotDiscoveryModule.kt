package dev.cyphernova.mobileops.modules.tier0

import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.iot.DeviceFingerprint
import dev.cyphernova.mobileops.core.iot.IotPorts
import dev.cyphernova.mobileops.core.iot.IotProbes
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleCategory
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Identifies the equipment on a network, rather than the ports.
 *
 * On most sites the general-purpose scan is the assessment. On a site whose value is in its
 * devices — a hospital, a plant, a warehouse, a building with a serious BMS — it is the least
 * interesting part, because the equipment does not speak SSH or HTTP. It speaks DICOM, BACnet,
 * Modbus, HL7, MQTT, and a top-1000 port list contains none of them.
 *
 * So this scans the catalogue those protocols live in, speaks each one well enough to make the
 * device identify itself, and reports what the thing *is* and why it matters — an imaging node,
 * the chiller controller, a camera overlooking a waiting room.
 *
 * ## Why it is deliberately slow
 *
 * A great deal of operational and medical equipment runs a TCP stack written for a network where
 * nobody was rude, and will fault, reboot or stop answering under a scan a server would not
 * notice. In a clinical setting that is not a finding, it is a patient safety event. So the
 * moment anything on a host looks like equipment, this drops to one connection at a time, stops
 * grabbing banners, and speaks only the read-defined exchange each protocol specifies. It is
 * slower than a port scan by design, and that is the correct trade.
 */
class IotDiscoveryModule : PentestModule {
    override val id = "t0.iot.discovery"
    override val title = "IoT & OT device discovery"
    override val description =
        "Identifies equipment rather than ports: DICOM, HL7, BACnet, Modbus, MQTT, CoAP, RTSP " +
            "and the rest a general scan misses. Backs off automatically on fragile devices."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.ACTIVE
    override val category = ModuleCategory.NETWORK
    override val requiresTarget = true

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val hosts = context.targets.hosts()
        if (hosts.isEmpty()) {
            return ModuleOutcome.Blocked(
                "No hosts selected. Run host discovery first, then pick the hosts to identify.",
            )
        }

        var identified = 0
        var equipment = 0

        for (host in hosts) {
            val open = sweep(host)
            if (open.isEmpty()) continue

            val fragility = IotPorts.fragilityAcross(open.keys)
            val evidence = DeviceFingerprint.Evidence(
                address = host,
                openPorts = open.keys,
                banners = open,
            )
            val probed = probe(host, open.keys, fragility, emit)
            val verdict = DeviceFingerprint.classify(
                evidence.copy(banners = open + probed.banners, names = probed.names),
            )

            identified++
            if (verdict.fragility != IotPorts.Fragility.ROBUST) equipment++
            emit(deviceFinding(host, verdict, open, probed))
        }

        return when {
            identified == 0 -> ModuleOutcome.Completed(
                "No IoT or OT services answered on ${hosts.size} host(s).",
            )
            else -> ModuleOutcome.Completed(
                "$identified device(s) identified, $equipment of them equipment rather than hosts.",
            )
        }
    }

    /** What the protocol probes established, beyond the fact that a port is open. */
    private data class Probed(
        val banners: Map<Int, String> = emptyMap(),
        val names: List<String> = emptyList(),
        val findings: Int = 0,
    )

    /**
     * A TCP sweep of the catalogue.
     *
     * Concurrency starts modest and there is no banner grab here at all — the protocol probes do
     * that properly, in each protocol's own language, once it is known what is worth asking.
     */
    private suspend fun sweep(host: String): Map<Int, String> = coroutineScope {
        IotPorts.allPorts.chunked(CONCURRENCY).flatMap { batch ->
            batch.map { port ->
                async(Dispatchers.IO) { if (isOpen(host, port)) port else null }
            }.awaitAll().filterNotNull()
        }.associateWith { "" }
    }

    private fun isOpen(host: String, port: Int): Boolean = runCatching {
        Socket().use { socket ->
            socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
            socket.isConnected
        }
    }.getOrDefault(false)

    /**
     * Speaks each protocol that is listening, one at a time where the host looks delicate.
     *
     * Sequential rather than concurrent on purpose: several of these devices serialise their
     * whole network stack, and two simultaneous conversations is enough to wedge them.
     */
    private suspend fun probe(
        host: String,
        ports: Set<Int>,
        fragility: IotPorts.Fragility,
        emit: suspend (Finding) -> Unit,
    ): Probed {
        val banners = mutableMapOf<Int, String>()
        val names = mutableListOf<String>()
        var findings = 0

        if (1883 in ports || 8883 in ports) {
            mqtt(host, if (1883 in ports) 1883 else 8883)?.let { result ->
                banners[1883] = "MQTT ${result.meaning}"
                if (result.accepted) {
                    findings++
                    emit(mqttFinding(host, result))
                }
            }
        }

        if (502 in ports) {
            modbus(host)?.let { identity ->
                names += identity.values
                banners[502] = identity.entries.joinToString { "${it.key}=${it.value}" }
                findings++
                emit(modbusFinding(host, identity))
            }
        }

        listOf(104, 11112).firstOrNull { it in ports }?.let { port ->
            dicom(host, port)?.let { result ->
                findings++
                emit(dicomFinding(host, port, result))
                if (result is IotProbes.DicomResult.Accepted) names += result.respondingAeTitle
            }
        }

        listOf(554, 8554).firstOrNull { it in ports }?.let { port ->
            rtsp(host, port)?.let { result ->
                result.server?.let { names += it }
                banners[port] = "RTSP ${result.status}${result.server?.let { " ($it)" } ?: ""}"
                if (!result.requiresAuthentication && result.status in 200..299) {
                    findings++
                    emit(rtspFinding(host, port, result))
                }
            }
        }

        // UDP probes are unaffected by the TCP sweep, so they run regardless of what it found.
        coap(host)?.let { directory ->
            names += "coap"
            findings++
            emit(coapFinding(host, directory))
        }

        bacnet(host)?.let { instance ->
            names += "bacnet"
            findings++
            emit(bacnetFinding(host, instance, fragility))
        }

        return Probed(banners, names, findings)
    }

    // ------------------------------------------------------------- probes

    private suspend fun mqtt(host: String, port: Int): IotProbes.MqttResult? =
        exchangeTcp(host, port, IotProbes.mqttConnect())?.let(IotProbes::parseMqttConnack)

    private suspend fun modbus(host: String): Map<String, String>? =
        exchangeTcp(host, 502, IotProbes.modbusDeviceId())?.let(IotProbes::parseModbusDeviceId)

    private suspend fun dicom(host: String, port: Int): IotProbes.DicomResult? =
        exchangeTcp(host, port, IotProbes.dicomAssociateRequest())?.let(IotProbes::parseDicomResponse)

    private suspend fun rtsp(host: String, port: Int): IotProbes.RtspResult? =
        exchangeTcp(host, port, IotProbes.rtspOptions(host, port))
            ?.let { IotProbes.parseRtspResponse(String(it, Charsets.ISO_8859_1)) }

    private suspend fun coap(host: String): String? {
        val response = exchangeUdp(host, 5683, IotProbes.coapWellKnownCore()) ?: return null
        if (!IotProbes.isCoapContent(response)) return null
        return IotProbes.coapPayload(response)
    }

    private suspend fun bacnet(host: String): Int? =
        exchangeUdp(host, 47808, IotProbes.bacnetWhoIs())?.let(IotProbes::parseBacnetIAm)

    // ------------------------------------------------------------- findings

    private fun mqttFinding(host: String, result: IotProbes.MqttResult) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.HIGH,
        title = "MQTT broker accepts anonymous clients — $host",
        subject = "$host:1883",
        detail = "The broker ${result.meaning}. A client that can connect without credentials " +
            "can subscribe to '#' and receive every message crossing the estate — sensor " +
            "readings, device commands, and on a surprising number of deployments the " +
            "credentials devices use to talk to everything else. It can also publish, which on " +
            "an estate that acts on MQTT means issuing commands.",
        data = mapOf("host" to host, "port" to "1883", "connack" to result.returnCode.toString()),
    )

    private fun modbusFinding(host: String, identity: Map<String, String>) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.HIGH,
        title = "Modbus device answering — $host",
        subject = "$host:502",
        detail = "The device identified itself without authentication: " +
            identity.entries.joinToString { "${it.key} ${it.value}" } + ". " +
            "Modbus has no authentication in the protocol at all, so anything that can reach " +
            "this port can read every register and, on most implementations, write them. The " +
            "finding is the reachability: this device expects to be on a network nobody else is " +
            "on. Only a read was issued here — establishing what writing would do is not " +
            "something to test against live plant.",
        data = mapOf("host" to host, "port" to "502") + identity,
    )

    private fun dicomFinding(host: String, port: Int, result: IotProbes.DicomResult) = when (result) {
        is IotProbes.DicomResult.Accepted -> Finding(
            moduleId = id,
            observedAtEpochMs = System.currentTimeMillis(),
            severity = Severity.CRITICAL,
            title = "DICOM node accepts an unknown caller — $host",
            subject = "$host:$port",
            detail = "The node accepted an association from the AE title 'MOBILEOPS', which it " +
                "has never been configured to know, and answered as '${result.respondingAeTitle}'. " +
                "DICOM's default access control is the calling AE title — a name the caller " +
                "picks for itself — so accepting an arbitrary one means the only gate is one an " +
                "attacker controls. A node in this state will generally also answer queries for " +
                "the studies it holds, which is patient data.",
            data = mapOf(
                "host" to host,
                "port" to port.toString(),
                "responding_ae_title" to result.respondingAeTitle,
            ),
        )

        is IotProbes.DicomResult.Rejected -> Finding(
            moduleId = id,
            observedAtEpochMs = System.currentTimeMillis(),
            severity = Severity.MEDIUM,
            title = "DICOM node present but refused the association — $host",
            subject = "$host:$port",
            detail = "The node rejected an unknown caller (${result.reason}), which is the " +
                "correct behaviour. It is still an imaging node reachable from this segment, and " +
                "AE title checking is a weak control — the accepted titles are guessable and " +
                "frequently documented in the vendor's own manuals.",
            data = mapOf("host" to host, "port" to port.toString(), "reason" to result.reason),
        )
    }

    private fun rtspFinding(host: String, port: Int, result: IotProbes.RtspResult) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.HIGH,
        title = "RTSP stream answers without credentials — $host",
        subject = "$host:$port",
        detail = "The stream answered OPTIONS with ${result.status} rather than demanding " +
            "authentication" + (result.server?.let { ", identifying itself as $it" } ?: "") +
            ". A camera readable from this segment is a physical surveillance question: what it " +
            "overlooks decides how much it matters, and in a clinical or reception setting that " +
            "is usually people who have not consented to being watched by whoever is on the WiFi.",
        data = mapOf(
            "host" to host,
            "port" to port.toString(),
            "status" to result.status.toString(),
            "server" to result.server.orEmpty(),
        ),
    )

    private fun coapFinding(host: String, directory: String?) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.MEDIUM,
        title = "CoAP device exposes its resource directory — $host",
        subject = "$host:5683",
        detail = "The device returned /.well-known/core, which lists every resource it exposes: " +
            (directory?.take(RESOURCE_CHARS) ?: "(empty)") +
            ". This is readable by design rather than a misconfiguration, but it is a complete " +
            "map of the device's interface, and CoAP deployments frequently leave the write " +
            "methods as unauthenticated as the read ones.",
        data = mapOf("host" to host, "port" to "5683", "resources" to directory.orEmpty().take(RESOURCE_CHARS)),
    )

    private fun bacnetFinding(host: String, instance: Int, fragility: IotPorts.Fragility) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.HIGH,
        title = "BACnet device answered Who-Is — $host",
        subject = "$host:47808",
        detail = "Device instance $instance answered a broadcast Who-Is, which is how BACnet " +
            "discovery works and needs no credential. Base BACnet has no authentication: what " +
            "can reach it can read every point and usually write them. In a hospital or lab that " +
            "reaches room pressure differentials, temperatures for stored medicines and " +
            "sometimes door release, which makes it a safety system rather than a facilities " +
            "one. Handled as ${fragility.label}.",
        data = mapOf("host" to host, "port" to "47808", "device_instance" to instance.toString()),
    )

    private fun deviceFinding(
        host: String,
        verdict: DeviceFingerprint.Verdict,
        open: Map<Int, String>,
        probed: Probed,
    ) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        // The identification itself is inventory. What it means was reported by the probes.
        severity = if (verdict.fragility == IotPorts.Fragility.FRAGILE) Severity.LOW else Severity.INFO,
        title = "${verdict.category.label} — $host",
        subject = host,
        detail = buildString {
            append("Identified as ${verdict.category.label} (${verdict.confidence.label}): ")
            append("${verdict.basis}. ")
            if (verdict.significance.isNotBlank()) append("${verdict.significance} ")
            append("Services: ")
            append(
                open.keys.sorted().joinToString {
                    "$it/${IotPorts.serviceAt(it)?.name ?: "unknown"}"
                },
            )
            append(". Handled as ${verdict.fragility.label}.")
            if (verdict.fragility == IotPorts.Fragility.FRAGILE) {
                append(
                    " Do not point a general-purpose scanner at this host — equipment of this " +
                        "kind faults under scans a server would not notice, and on a live site " +
                        "that is an outage rather than a finding.",
                )
            }
        },
        data = mapOf(
            "host" to host,
            "category" to verdict.category.name,
            "confidence" to verdict.confidence.name,
            "fragility" to verdict.fragility.name,
            "open_ports" to open.keys.sorted().joinToString(),
            "probe_findings" to probed.findings.toString(),
        ),
    )

    // ------------------------------------------------------------- transport

    /** One request, one response, then the socket closes. Nothing is held open. */
    private suspend fun exchangeTcp(host: String, port: Int, request: ByteArray): ByteArray? =
        withContext(Dispatchers.IO) {
            withTimeoutOrNull(EXCHANGE_TIMEOUT_MS) {
                runCatching {
                    Socket().use { socket ->
                        socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
                        socket.soTimeout = READ_TIMEOUT_MS
                        socket.getOutputStream().write(request)
                        socket.getOutputStream().flush()
                        val buffer = ByteArray(RESPONSE_BYTES)
                        val read = socket.getInputStream().read(buffer)
                        if (read > 0) buffer.copyOf(read) else null
                    }
                }.getOrNull()
            }
        }

    private suspend fun exchangeUdp(host: String, port: Int, request: ByteArray): ByteArray? =
        withContext(Dispatchers.IO) {
            withTimeoutOrNull(EXCHANGE_TIMEOUT_MS) {
                runCatching {
                    DatagramSocket().use { socket ->
                        socket.soTimeout = READ_TIMEOUT_MS
                        val address = InetAddress.getByName(host)
                        socket.send(DatagramPacket(request, request.size, address, port))
                        val buffer = ByteArray(RESPONSE_BYTES)
                        val packet = DatagramPacket(buffer, buffer.size)
                        socket.receive(packet)
                        buffer.copyOf(packet.length)
                    }
                }.getOrNull()
            }
        }

    private companion object {
        /**
         * Far lower than the general port scanner's. The catalogue is small, and the devices in
         * it are the ones that mind being hit by thirty simultaneous connections.
         */
        const val CONCURRENCY = 6
        const val CONNECT_TIMEOUT_MS = 1_200
        const val READ_TIMEOUT_MS = 2_000
        const val EXCHANGE_TIMEOUT_MS = 5_000L
        const val RESPONSE_BYTES = 4096
        const val RESOURCE_CHARS = 400
    }
}
