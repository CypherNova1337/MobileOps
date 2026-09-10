package dev.cyphernova.mobileops.modules.tier0

import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.exploit.Credential
import dev.cyphernova.mobileops.core.exploit.DefaultCredentials
import dev.cyphernova.mobileops.core.exploit.HttpAnalysis
import dev.cyphernova.mobileops.core.module.Intrusiveness
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
                val root = LanHttpClient.probe(base) ?: return@forEach

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

                val working = tryCredentials(base, DefaultCredentials.forVendor(vendor))
                if (working != null) {
                    accepted++
                    emit(
                        Finding(
                            moduleId = id,
                            observedAtEpochMs = System.currentTimeMillis(),
                            severity = Severity.CRITICAL,
                            title = "Default credentials accepted at $base",
                            subject = base,
                            detail = "The pair '$working' was accepted. This is full administrative " +
                                "access to the device from anywhere on this network, and it is the " +
                                "finding everything else on this host is downstream of. Change it " +
                                "before anything else.",
                            data = mapOf(
                                "username" to working.username,
                                "vendor" to working.vendor,
                                "realm" to realm.orEmpty(),
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

    private suspend fun tryCredentials(base: String, credentials: List<Credential>): Credential? {
        credentials.forEach { credential ->
            // Spaced out: rapid-fire attempts are what trigger lockouts and reboots on the
            // small appliances this is most often pointed at.
            delay(ATTEMPT_SPACING_MS)

            val response = LanHttpClient.probe(
                url = base,
                authorization = HttpAnalysis.basicAuthHeader(credential.username, credential.password),
            ) ?: return@forEach

            if (HttpAnalysis.credentialsAccepted(response)) return credential
        }
        return null
    }

    private companion object {
        const val ATTEMPT_SPACING_MS = 250L
        val PORTS = listOf(80 to "http", 8080 to "http", 443 to "https", 8443 to "https")
    }
}
