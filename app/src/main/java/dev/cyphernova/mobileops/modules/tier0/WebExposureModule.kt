package dev.cyphernova.mobileops.modules.tier0

import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.exploit.HttpAnalysis
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule
import kotlinx.coroutines.delay

/**
 * Looks for what a web interface gives away before anyone logs in.
 *
 * Read-only: every request is a GET. Nothing here changes state on the target, which keeps it
 * safe to run against live equipment — the findings are about what is reachable, and reaching it
 * is the whole proof.
 */
class WebExposureModule : PentestModule {
    override val id = "t0.exploit.webexposure"
    override val title = "Web exposure check"
    override val description =
        "Probes selected hosts for unauthenticated admin pages, directory listings, exposed config " +
            "and version control, and missing security headers. GET requests only."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.ACTIVE
    override val requiresTarget = true

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val hosts = context.targets.hosts()
        if (hosts.isEmpty()) return ModuleOutcome.Blocked("No hosts selected.")

        var findings = 0
        var reachable = 0

        hosts.forEach { host ->
            PORTS.forEach { (port, scheme) ->
                val base = "$scheme://$host:$port"
                val root = LanHttpClient.probe(base) ?: return@forEach
                reachable++

                emit(
                    Finding(
                        moduleId = id,
                        observedAtEpochMs = System.currentTimeMillis(),
                        severity = Severity.INFO,
                        title = "Web interface at $base",
                        subject = base,
                        detail = buildString {
                            append("HTTP ${root.status}. ")
                            root.server?.let { append("Server banner: '$it'. ") }
                            root.basicAuthRealm?.let { append("Basic auth realm: '$it'. ") }
                            if (HttpAnalysis.looksLikeLoginForm(root)) append("Serves a login form. ")
                        },
                        data = mapOf(
                            "status" to root.status.toString(),
                            "server" to root.server.orEmpty(),
                            "realm" to root.basicAuthRealm.orEmpty(),
                        ),
                    ),
                )

                // A banner naming the product and firmware is the fastest route from "a device is
                // here" to a list of known vulnerabilities for it.
                root.server?.takeIf { it.any(Char::isDigit) }?.let { banner ->
                    findings++
                    emit(
                        Finding(
                            moduleId = id,
                            observedAtEpochMs = System.currentTimeMillis(),
                            severity = Severity.LOW,
                            title = "Server banner discloses version",
                            subject = base,
                            detail = "The server identifies itself as '$banner', which is enough to " +
                                "look up firmware-specific vulnerabilities without probing further.",
                            data = mapOf("server" to banner),
                        ),
                    )
                }

                if (root.isSuccess && !HttpAnalysis.looksLikeLoginForm(root)) {
                    findings++
                    emit(
                        Finding(
                            moduleId = id,
                            observedAtEpochMs = System.currentTimeMillis(),
                            severity = Severity.MEDIUM,
                            title = "Web root served without authentication",
                            subject = base,
                            detail = "The root page returns ${root.status} with no login prompt or " +
                                "form. Whatever it exposes is reachable by anyone on this network.",
                        ),
                    )
                }

                HttpAnalysis.missingSecurityHeaders(root).takeIf { it.isNotEmpty() }?.let { missing ->
                    findings++
                    emit(
                        Finding(
                            moduleId = id,
                            observedAtEpochMs = System.currentTimeMillis(),
                            severity = Severity.LOW,
                            title = "Missing security headers",
                            subject = base,
                            detail = "Absent: ${missing.joinToString()}. On an admin interface these " +
                                "are what stop a malicious page in another tab from framing or " +
                                "driving it.",
                            data = mapOf("missing" to missing.joinToString()),
                        ),
                    )
                }

                // Baseline control. Ask for a path that cannot exist. If the device answers it
                // with a 200, it answers everything with a 200, and every "exposed path" below
                // would be the same page wearing different names — which is exactly what it
                // looked like when nine unrelated paths all returned an identical 2489 bytes.
                val baseline = LanHttpClient.probe("$base/$CONTROL_PATH")
                val answersEverything = baseline != null &&
                    baseline.isSuccess &&
                    !HttpAnalysis.isSoftError(baseline)

                if (answersEverything) {
                    findings++
                    emit(
                        Finding(
                            moduleId = id,
                            observedAtEpochMs = System.currentTimeMillis(),
                            severity = Severity.LOW,
                            title = "Answers every path identically",
                            subject = base,
                            detail = "A deliberately nonexistent path returned HTTP " +
                                "${baseline!!.status} with ${baseline.body.length} bytes" +
                                (HttpAnalysis.pageTitle(baseline)?.let { ", titled '$it'" } ?: "") +
                                ". This device does not distinguish a real path from an invented " +
                                "one, so path probing cannot tell you anything here and was " +
                                "skipped. Anything genuinely exposed must be found by hand.",
                            data = mapOf(
                                "control_status" to baseline.status.toString(),
                                "control_bytes" to baseline.body.length.toString(),
                            ),
                        ),
                    )
                    return@forEach
                }

                SENSITIVE_PATHS.forEach { (path, description) ->
                    delay(REQUEST_SPACING_MS)
                    val response = LanHttpClient.probe("$base$path") ?: return@forEach
                    if (!response.isSuccess || HttpAnalysis.isSoftError(response)) return@forEach
                    if (response.body.isBlank()) return@forEach
                    // Byte-identical to the known-bad path means it is that page, not this one.
                    if (baseline != null && response.body.length == baseline.body.length) return@forEach

                    findings++
                    emit(
                        Finding(
                            moduleId = id,
                            observedAtEpochMs = System.currentTimeMillis(),
                            severity = severityForPath(path),
                            title = "Exposed: $path",
                            subject = "$base$path",
                            detail = "$description Returned ${response.status} with " +
                                "${response.body.length} bytes and no authentication." +
                                if (HttpAnalysis.isDirectoryListing(response)) " Directory listing is enabled." else "",
                            data = mapOf(
                                "path" to path,
                                "status" to response.status.toString(),
                                "bytes" to response.body.length.toString(),
                            ),
                        ),
                    )
                }
            }
        }

        return if (reachable == 0) {
            ModuleOutcome.Completed("No web interface answered on the selected host(s).")
        } else {
            ModuleOutcome.Completed("$findings finding(s) across $reachable web interface(s).")
        }
    }

    private fun severityForPath(path: String): Severity = when {
        path.contains(".git") || path.contains(".env") || path.contains("backup") -> Severity.HIGH
        path.contains("config") || path.contains("phpinfo") -> Severity.HIGH
        path.contains("status") || path.contains("info") -> Severity.MEDIUM
        else -> Severity.MEDIUM
    }

    private companion object {
        const val REQUEST_SPACING_MS = 60L

        /** A path no device could legitimately serve, used to detect catch-all responders. */
        const val CONTROL_PATH = "mobileops-control-9f2a7c41"

        val PORTS = listOf(80 to "http", 8080 to "http", 443 to "https", 8443 to "https")

        /** Small and high-signal: each of these is a real finding when it answers. */
        val SENSITIVE_PATHS = listOf(
            "/.git/config" to "A git repository is served, exposing source and often credentials in history.",
            "/.env" to "An environment file is served, which conventionally holds secrets.",
            "/backup" to "A backup path is reachable without authentication.",
            "/config" to "A configuration path is reachable without authentication.",
            "/config.xml" to "A configuration file is served directly.",
            "/phpinfo.php" to "phpinfo discloses the full server configuration.",
            "/server-status" to "Apache server-status exposes live requests and client addresses.",
            "/admin" to "An admin path answers without authentication.",
            "/cgi-bin/" to "The CGI directory is listable.",
            "/setup.cgi" to "A setup endpoint is reachable, common on consumer routers.",
        )
    }
}
