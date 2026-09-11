package dev.cyphernova.mobileops.modules.tier0

import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.exploit.HttpAnalysis
import dev.cyphernova.mobileops.core.exploit.PathEvidence
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleCategory
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
    override val category = ModuleCategory.EXPLOIT
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

                // Every signal the response carries, not just the absence of a password field.
                // A page titled "401 Unauthorized" served with a 200 is the device refusing, and
                // calling that unauthenticated access is a finding that is not there.
                if (root.isSuccess && !HttpAnalysis.deniesAccess(root)) {
                    findings++
                    emit(
                        Finding(
                            moduleId = id,
                            observedAtEpochMs = System.currentTimeMillis(),
                            severity = Severity.MEDIUM,
                            title = "Web root served without authentication",
                            subject = base,
                            detail = "The root page returns ${root.status} with no login form, no " +
                                "authentication challenge, and nothing in its title or body that " +
                                "says it is refusing. Whatever it exposes is reachable by anyone " +
                                "on this network." +
                                (HttpAnalysis.pageTitle(root)?.let { " Titled '$it'." } ?: ""),
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

                // Baseline control. Ask for paths that cannot exist. A device that answers
                // those with a 200 answers everything with a 200, and every "exposed path" below
                // would be the same page wearing different names — which is what it looked like
                // when nine unrelated paths all came back an identical 2489 bytes.
                //
                // Two of them, because one request that simply times out used to leave the
                // baseline null, and the filter below was written to skip itself when that
                // happened. A control that disables itself on error is not a control.
                val controls = CONTROL_PATHS.mapNotNull { control ->
                    delay(REQUEST_SPACING_MS)
                    LanHttpClient.probe("$base/$control")
                }

                if (!PathEvidence.canProbePaths(controls.size)) {
                    // Fail closed. Without a baseline there is no way to tell a real path from a
                    // catch-all, and reporting them anyway is how the false positives got out.
                    findings++
                    emit(
                        Finding(
                            moduleId = id,
                            observedAtEpochMs = System.currentTimeMillis(),
                            severity = Severity.INFO,
                            title = "Path probing skipped on $base",
                            subject = base,
                            detail = "Neither control request completed, so there is no way to tell " +
                                "whether this device distinguishes a real path from an invented " +
                                "one. Path findings are only meaningful against that baseline, so " +
                                "none were produced. The host answered its root, so it is worth " +
                                "trying again or looking by hand.",
                            data = mapOf("controls_attempted" to CONTROL_PATHS.size.toString()),
                        ),
                    )
                    return@forEach
                }

                val answeringControl = controls.firstOrNull { control ->
                    control.isSuccess && !HttpAnalysis.isSoftError(control)
                }

                if (answeringControl != null) {
                    findings++
                    emit(
                        Finding(
                            moduleId = id,
                            observedAtEpochMs = System.currentTimeMillis(),
                            severity = Severity.LOW,
                            title = "Answers every path identically",
                            subject = base,
                            detail = "A deliberately nonexistent path returned HTTP " +
                                "${answeringControl.status} with ${answeringControl.body.length} bytes" +
                                (HttpAnalysis.pageTitle(answeringControl)?.let { ", titled '$it'" } ?: "") +
                                ". This device does not distinguish a real path from an invented " +
                                "one, so path probing cannot tell you anything here and was " +
                                "skipped. Anything genuinely exposed must be found by hand.",
                            data = mapOf(
                                "control_status" to answeringControl.status.toString(),
                                "control_bytes" to answeringControl.body.length.toString(),
                            ),
                        ),
                    )
                    return@forEach
                }

                // Everything a real path must not look like: any control's body, and the root.
                // A single-page admin interface serves its shell for every unknown path, and the
                // shell is usually the root.
                val decoys = (controls + root).map { it.body.length }.toSet()

                // Collected before anything is reported, because the decisive evidence is how
                // the responses compare with each other. Three paths returning byte-identical
                // bodies are one page under three names, and that is invisible while each is
                // judged on its own.
                val probed = SENSITIVE_PATHS.mapNotNull { (path, description) ->
                    delay(REQUEST_SPACING_MS)
                    val response = LanHttpClient.probe("$base$path") ?: return@mapNotNull null
                    if (!response.isSuccess || HttpAnalysis.isSoftError(response)) return@mapNotNull null
                    if (response.body.isBlank()) return@mapNotNull null
                    Triple(path, description, response)
                }

                // Any body size that turns up for more than one path is a shared page rather
                // than something each of those paths exposes.
                val shared = probed.groupingBy { it.third.body.length }
                    .eachCount()
                    .filterValues { it > 1 }
                    .keys

                probed.forEach { (path, description, response) ->
                    // The same size as a page known not to exist, as the root, or as another
                    // probed path, means this is that page under another name.
                    if (!PathEvidence.isDistinct(response.body.length, decoys + shared)) return@forEach
                    // A page that refuses — by challenge, by login form, by a denial in the
                    // body, or by a title that says so — is the control working, not a way past
                    // it. The title is the one that caught a router serving "401 Unauthorized"
                    // with a 200 and being reported as an exposed setup endpoint.
                    if (HttpAnalysis.deniesAccess(response)) return@forEach

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
                                (if (HttpAnalysis.isDirectoryListing(response)) {
                                    " Directory listing is enabled."
                                } else {
                                    ""
                                }) +
                                (HttpAnalysis.pageTitle(response)?.let { " Titled '$it'." } ?: ""),
                            data = mapOf(
                                "path" to path,
                                "status" to response.status.toString(),
                                "bytes" to response.body.length.toString(),
                                // Carried so a surprising finding can be checked against what the
                                // controls returned rather than taken on trust.
                                "control_bytes" to controls.joinToString { it.body.length.toString() },
                                "root_bytes" to root.body.length.toString(),
                            ),
                        ),
                    )
                }

                if (shared.isNotEmpty()) {
                    val sharedPaths = probed.filter { it.third.body.length in shared }.map { it.first }
                    findings++
                    emit(
                        Finding(
                            moduleId = id,
                            observedAtEpochMs = System.currentTimeMillis(),
                            severity = Severity.INFO,
                            title = "One page served for several paths on $base",
                            subject = base,
                            detail = "${sharedPaths.joinToString()} all returned bodies of the same " +
                                "size (${shared.joinToString()} bytes), so this is one page under " +
                                "several names rather than something each path exposes, and none " +
                                "of them is reported as a finding. It does differ from what an " +
                                "invented path returns, so those paths probably do exist — behind " +
                                "a login, which is the arrangement working rather than failing.",
                            data = mapOf(
                                "paths" to sharedPaths.joinToString(),
                                "bytes" to shared.joinToString(),
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
        /**
         * Two, so a single failed request cannot leave the module without a baseline. Both are
         * shaped like a real path and neither can exist.
         */
        val CONTROL_PATHS = listOf(
            "mobileops-control-9f2a7c41",
            "status/mobileops-control-3d81e6b2.cgi",
        )

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
