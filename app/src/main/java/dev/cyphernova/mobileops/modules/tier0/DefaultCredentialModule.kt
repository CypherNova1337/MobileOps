package dev.cyphernova.mobileops.modules.tier0

import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.exploit.Credential
import dev.cyphernova.mobileops.core.exploit.DefaultCredentials
import dev.cyphernova.mobileops.core.exploit.HttpAnalysis
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleCategory
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule
import kotlinx.coroutines.delay

/**
 * Tests whether a device still has the credentials it shipped with.
 *
 * This is exploitation rather than recon: a success here is access, and it is reported as such.
 * Scope is deliberately narrow — HTTP Basic auth only, a couple of dozen vendor defaults, and it
 * stops on the first pair that works. That is enough to prove the finding, and it keeps the
 * module away from being a password cracker: long lists against live equipment trip lockouts and
 * take devices off the network, which is a denial of service, not a test result.
 *
 * Form-based logins are detected and reported rather than driven, because every vendor's form
 * differs and a wrong guess submits junk to a live device.
 */
class DefaultCredentialModule : PentestModule {
    override val id = "t0.exploit.defaultcreds"
    override val title = "Default credential check"
    override val description =
        "Tests vendor default credentials against HTTP Basic auth on selected hosts. Stops at the " +
            "first pair that works; form logins are reported, not driven."
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

        var tested = 0
        var accepted = 0

        hosts.forEach { host ->
            PORTS.forEach { (port, scheme) ->
                val base = "$scheme://$host:$port"
                // A host skipped in silence is indistinguishable from a host with nothing
                // on it. The port was open enough to be worth trying, so why it did not answer
                // belongs in the log.
                val rootAttempt = LanHttpClient.attempt(base)
                val root = (rootAttempt as? LanHttpClient.Attempt.Answered)?.response
                if (root == null) {
                    emit(
                        Finding(
                            moduleId = id,
                            observedAtEpochMs = System.currentTimeMillis(),
                            severity = Severity.INFO,
                            title = "No HTTP reply from $base",
                            subject = base,
                            detail = "Nothing usable came back, so nothing below was tested " +
                                "against this endpoint: ${rootAttempt.describe()}.",
                            data = mapOf("attempted" to rootAttempt.describe()),
                        ),
                    )
                    return@forEach
                }

                if (!root.challengesBasicAuth) {
                    if (HttpAnalysis.looksLikeLoginForm(root)) {
                        emit(
                            Finding(
                                moduleId = id,
                                observedAtEpochMs = System.currentTimeMillis(),
                                severity = Severity.INFO,
                                title = "Form login at $base",
                                subject = base,
                                detail = "This interface uses a form login rather than HTTP Basic, so " +
                                    "it is not tested automatically. Try the vendor defaults by hand: " +
                                    "every form differs and submitting guesses blind risks locking the " +
                                    "account or the device.",
                            ),
                        )
                    }
                    return@forEach
                }

                tested++
                val realm = root.basicAuthRealm
                val vendor = realm?.let { text ->
                    DefaultCredentials.common.map { it.vendor }.distinct()
                        .firstOrNull { it != "generic" && text.contains(it, ignoreCase = true) }
                }

                emit(
                    Finding(
                        moduleId = id,
                        observedAtEpochMs = System.currentTimeMillis(),
                        severity = Severity.INFO,
                        title = "Basic auth challenge at $base",
                        subject = base,
                        detail = "Realm '${realm ?: "unnamed"}'" +
                            (vendor?.let { ", which names $it" } ?: "") +
                            ". Testing ${DefaultCredentials.common.size} default pair(s).",
                    ),
                )

                // Negative control. Send a credential that cannot possibly be right; if the
                // device answers it the same way it answers a correct one, then nothing this
                // module observes afterwards means anything, and reporting a CRITICAL finding
                // off the back of it would be inventing access that does not exist.
                val control = LanHttpClient.probe(
                    url = base,
                    authorization = HttpAnalysis.basicAuthHeader(CONTROL_USER, CONTROL_PASSWORD),
                )
                if (control == null || HttpAnalysis.credentialsAccepted(control)) {
                    emit(
                        Finding(
                            moduleId = id,
                            observedAtEpochMs = System.currentTimeMillis(),
                            severity = Severity.INFO,
                            title = "Credential testing inconclusive at $base",
                            subject = base,
                            detail = "A deliberately invalid credential was " +
                                (if (control == null) "not answered at all" else
                                    "accepted (HTTP ${control.status}" +
                                        (HttpAnalysis.pageTitle(control)?.let { ", page '$it'" } ?: "") + ")") +
                                ". This device does not distinguish a wrong password from a right " +
                                "one in a way that can be detected from outside, so no credential " +
                                "result from it would be trustworthy. Test this interface by hand.",
                            data = mapOf(
                                "control_status" to (control?.status?.toString() ?: "no response"),
                                "control_title" to (control?.let(HttpAnalysis::pageTitle).orEmpty()),
                            ),
                        ),
                    )
                    return@forEach
                }

                val hit = tryCredentials(base, DefaultCredentials.forVendor(vendor))
                val working = hit?.first
                if (working != null) {
                    val evidence = hit.second
                    accepted++
                    emit(
                        Finding(
                            moduleId = id,
                            observedAtEpochMs = System.currentTimeMillis(),
                            severity = Severity.CRITICAL,
                            title = "Default credentials accepted at $base",
                            subject = base,
                            detail = "The pair '$working' was accepted where an invalid control " +
                                "credential was refused, so the device does discriminate. It " +
                                "answered HTTP ${evidence.status} with ${evidence.body.length} bytes" +
                                (HttpAnalysis.pageTitle(evidence)?.let { ", page titled '$it'" } ?: "") +
                                ". Verify by hand before reporting: open $base in a browser and " +
                                "enter $working. If the browser disagrees, treat this as a false " +
                                "positive and tell me what it showed.",
                            data = mapOf(
                                "username" to working.username,
                                "vendor" to working.vendor,
                                "realm" to realm.orEmpty(),
                                "status" to evidence.status.toString(),
                                "bytes" to evidence.body.length.toString(),
                                "page_title" to HttpAnalysis.pageTitle(evidence).orEmpty(),
                            ),
                        ),
                    )
                } else {
                    emit(
                        Finding(
                            moduleId = id,
                            observedAtEpochMs = System.currentTimeMillis(),
                            severity = Severity.INFO,
                            title = "Default credentials rejected at $base",
                            subject = base,
                            detail = "None of the ${DefaultCredentials.common.size} tested default " +
                                "pairs were accepted. This says the shipped credentials are gone, " +
                                "not that the password is strong.",
                        ),
                    )
                }
            }
        }

        return when {
            tested == 0 -> ModuleOutcome.Completed("No HTTP Basic auth challenge found on the selected host(s).")
            accepted > 0 -> ModuleOutcome.Completed("$accepted of $tested interface(s) accepted default credentials.")
            else -> ModuleOutcome.Completed("$tested interface(s) tested, none accepted defaults.")
        }
    }

    /** Returns the pair that worked along with the response that proves it. */
    private suspend fun tryCredentials(
        base: String,
        credentials: List<Credential>,
    ): Pair<Credential, dev.cyphernova.mobileops.core.exploit.HttpResponse>? {
        credentials.forEach { credential ->
            // Spaced out: rapid-fire attempts are what trigger lockouts and reboots on the
            // small appliances this is most often pointed at.
            delay(ATTEMPT_SPACING_MS)

            val response = LanHttpClient.probe(
                url = base,
                authorization = HttpAnalysis.basicAuthHeader(credential.username, credential.password),
            ) ?: return@forEach

            if (HttpAnalysis.credentialsAccepted(response)) return credential to response
        }
        return null
    }

    private companion object {
        const val ATTEMPT_SPACING_MS = 250L
        const val CONTROL_USER = "mobileops-control"
        const val CONTROL_PASSWORD = "nx8Qv2-not-a-real-password-4Kd1"
        val PORTS = listOf(80 to "http", 8080 to "http", 443 to "https", 8443 to "https")
    }
}
