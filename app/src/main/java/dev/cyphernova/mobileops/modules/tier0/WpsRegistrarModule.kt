package dev.cyphernova.mobileops.modules.tier0

import dev.cyphernova.mobileops.core.beacon.BeaconElements
import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.exploit.UpnpWps
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule

/**
 * Tests whether the WPS External Registrar is reachable over UPnP without authentication.
 *
 * This is the only classic WiFi attack an unrooted phone can actually reach. WPS normally runs
 * over 802.11 EAP frames, which needs monitor mode and injection — Tier 2. But the same
 * registrar protocol is also exposed over UPnP/SOAP on many consumer routers, and that path is
 * ordinary HTTP over the LAN.
 *
 * It matters because it sidesteps every WPS defence that operates at the radio. An AP with its
 * WPS PIN locked — refusing PIN attempts over the air — can still answer the registrar over
 * UPnP, because the lock and the UPnP service are different code paths.
 *
 * This module establishes reachability and stops there: it sends GetDeviceInfo and reports what
 * came back. Completing the registrar exchange to extract the passphrase is the next step, and
 * it is worth taking only once this has confirmed the door is open.
 */
class WpsRegistrarModule : PentestModule {
    override val id = "t0.exploit.wpsregistrar"
    override val title = "WPS registrar over UPnP"
    override val description =
        "Tests whether the WPS External Registrar answers unauthenticated over UPnP — the one WPS " +
            "attack surface reachable without monitor mode. Bypasses radio-side PIN locking."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.ACTIVE
    override val requiresTarget = true

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val hosts = context.targets.hosts()
        if (hosts.isEmpty()) return ModuleOutcome.Blocked("No hosts selected.")

        var probed = 0
        var reachable = 0

        hosts.forEach { host ->
            val description = findDescription(host) ?: return@forEach
            probed++

            val service = UpnpWps.findWpsService(description.second, description.first)
            if (service == null) {
                emit(
                    Finding(
                        moduleId = id,
                        observedAtEpochMs = System.currentTimeMillis(),
                        severity = Severity.INFO,
                        title = "No WPS registrar service on $host",
                        subject = host,
                        detail = "The UPnP description at ${description.first} does not advertise " +
                            "WFAWLANConfig, so there is no registrar reachable over UPnP here.",
                    ),
                )
                return@forEach
            }

            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    severity = Severity.INFO,
                    title = "WPS registrar endpoint on $host",
                    subject = service.controlUrl,
                    detail = "The device advertises ${service.serviceType} with its control endpoint " +
                        "at ${service.controlUrl}. Sending an unauthenticated GetDeviceInfo.",
                    data = mapOf("control_url" to service.controlUrl),
                ),
            )

            val response = LanHttpClient.probe(
                url = service.controlUrl,
                method = "POST",
                body = UpnpWps.getDeviceInfoEnvelope(service.serviceType),
                headers = mapOf(
                    "Content-Type" to "text/xml; charset=\"utf-8\"",
                    "SOAPAction" to UpnpWps.soapAction(service.serviceType, UpnpWps.ACTION_GET_DEVICE_INFO),
                ),
                timeoutMs = 8_000,
            )

            if (response == null) {
                emit(
                    Finding(
                        moduleId = id,
                        observedAtEpochMs = System.currentTimeMillis(),
                        severity = Severity.INFO,
                        title = "Registrar did not answer on $host",
                        subject = service.controlUrl,
                        detail = "No response to GetDeviceInfo. The service is advertised but the " +
                            "control endpoint is not answering.",
                    ),
                )
                return@forEach
            }

            val deviceInfo = UpnpWps.extractDeviceInfo(response.body)
            when {
                deviceInfo != null -> {
                    reachable++
                    // M1 uses the same attribute encoding as the beacon's WPS element, so the
                    // parser written for beacons reads it directly.
                    val wps = BeaconElements.parseWps(deviceInfo)
                    emit(
                        Finding(
                            moduleId = id,
                            observedAtEpochMs = System.currentTimeMillis(),
                            severity = Severity.HIGH,
                            title = "WPS registrar answers unauthenticated on $host",
                            subject = service.controlUrl,
                            detail = buildString {
                                append(
                                    "GetDeviceInfo returned a ${deviceInfo.size}-byte WPS M1 message " +
                                        "with no authentication. M1 is the first message of the " +
                                        "registrar exchange, so the protocol has begun with an " +
                                        "unauthenticated caller. ",
                                )
                                wps?.let { info ->
                                    info.manufacturer?.let { append("Manufacturer $it. ") }
                                    info.modelName?.let { append("Model $it. ") }
                                    info.serialNumber?.let { append("Serial $it. ") }
                                    info.version?.let { append("WPS $it. ") }
                                }
                                append(
                                    "This path is independent of the radio-side PIN lock: an AP that " +
                                        "refuses PIN attempts over the air can still be driven here. " +
                                        "On vulnerable firmware, completing the exchange returns the " +
                                        "WPA passphrase. Disable WPS and UPnP on the LAN.",
                                )
                            },
                            data = buildMap {
                                put("control_url", service.controlUrl)
                                put("m1_bytes", deviceInfo.size.toString())
                                wps?.let { info ->
                                    put("manufacturer", info.manufacturer.orEmpty())
                                    put("model", info.modelName.orEmpty())
                                    put("serial", info.serialNumber.orEmpty())
                                    put("wps_version", info.version.orEmpty())
                                }
                            },
                        ),
                    )
                }

                UpnpWps.isSoapFault(response.body) -> {
                    emit(
                        Finding(
                            moduleId = id,
                            observedAtEpochMs = System.currentTimeMillis(),
                            severity = Severity.INFO,
                            title = "Registrar refused the request on $host",
                            subject = service.controlUrl,
                            detail = "GetDeviceInfo was refused" +
                                (UpnpWps.faultCode(response.body)?.let { " with UPnP error $it" } ?: "") +
                                ". The registrar is advertised but will not talk to an " +
                                "unauthenticated caller, which is the correct behaviour.",
                            data = mapOf("error_code" to UpnpWps.faultCode(response.body).orEmpty()),
                        ),
                    )
                }

                else -> {
                    emit(
                        Finding(
                            moduleId = id,
                            observedAtEpochMs = System.currentTimeMillis(),
                            severity = Severity.INFO,
                            title = "Unrecognised registrar response on $host",
                            subject = service.controlUrl,
                            detail = "The endpoint answered HTTP ${response.status} with " +
                                "${response.body.length} bytes containing no M1 message and no SOAP " +
                                "fault. Worth looking at by hand.",
                            data = mapOf("status" to response.status.toString()),
                        ),
                    )
                }
            }
        }

        return when {
            probed == 0 -> ModuleOutcome.Completed("No UPnP device description found on the selected host(s).")
            reachable > 0 -> ModuleOutcome.Completed("$reachable registrar(s) answered unauthenticated.")
            else -> ModuleOutcome.Completed("$probed device(s) probed, none exposed an open registrar.")
        }
    }

    /** Finds a UPnP description document on the ports these services habitually use. */
    private suspend fun findDescription(host: String): Pair<String, String>? {
        DESCRIPTION_CANDIDATES.forEach { (port, path) ->
            val url = "http://$host:$port$path"
            val response = LanHttpClient.probe(url, timeoutMs = 3_000) ?: return@forEach
            if (response.isSuccess && response.body.contains("<serviceType>", ignoreCase = true)) {
                return url to response.body
            }
        }
        return null
    }

    private companion object {
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
