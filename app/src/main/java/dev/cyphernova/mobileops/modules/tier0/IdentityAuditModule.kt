package dev.cyphernova.mobileops.modules.tier0

import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.identity.IdentityProbe
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleCategory
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule

/**
 * Reports the identity this device presents to a network, and what the selected profile would
 * change if it could be applied. Answers "what am I leaking" before anything is spoofed.
 */
class IdentityAuditModule : PentestModule {
    override val id = "t0.identity.audit"
    override val title = "Device identity audit"
    override val description =
        "Reports what the network can learn about this handset — DHCP hostname, MAC randomisation " +
            "behaviour, what the platform will and will not let an app read or change."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.PASSIVE
    override val category = ModuleCategory.DEVICE

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val surface = IdentityProbe.probe(context.androidContext, context.capabilities.rooted)
        val profile = context.profile

        emit(
            Finding(
                moduleId = id,
                observedAtEpochMs = System.currentTimeMillis(),
                severity = Severity.INFO,
                title = "Identity surface",
                subject = surface.deviceName ?: "this device",
                detail = buildString {
                    append("DHCP hostname: ${surface.deviceName ?: "unset"}. ")
                    append("MAC as reported to apps: ${surface.reportedMac ?: "unavailable"}. ")
                    append(
                        if (surface.realMacReadable) {
                            "Real hardware address readable: ${surface.realMac}."
                        } else {
                            "Real hardware address not readable at this tier."
                        },
                    )
                },
                data = mapOf(
                    "device_name" to surface.deviceName.orEmpty(),
                    "reported_mac" to surface.reportedMac.orEmpty(),
                    "real_mac" to surface.realMac.orEmpty(),
                    "platform_randomises_mac" to surface.platformRandomisesMac.toString(),
                ),
            ),
        )

        // One finding carrying every note, rather than a finding per note: they are all the same
        // observation about the same device, and as separate entries they drowned the report.
        if (surface.notes.isNotEmpty()) {
            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    severity = Severity.INFO,
                    title = "What the platform will and will not expose",
                    subject = surface.deviceName ?: "this device",
                    detail = surface.notes.joinToString("\n\n") { "• $it" },
                    data = mapOf("note_count" to surface.notes.size.toString()),
                ),
            )
        }

        // The hostname is the identifier people forget, because MAC randomisation gets all the
        // attention and then the lease table still says whose phone it is.
        surface.deviceName?.takeIf { it.isNotBlank() && looksPersonal(it) }?.let { name ->
            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    severity = Severity.MEDIUM,
                    title = "Device name identifies its owner",
                    subject = name,
                    detail = "'$name' is broadcast as the DHCP hostname and will appear in the " +
                        "network's lease table and in most NAC consoles. MAC randomisation does " +
                        "nothing about this. Changing it needs Tier 1.",
                ),
            )
        }

        val summary = if (profile.id == "passthrough") {
            "Identity reported. No profile selected, so nothing would be rewritten."
        } else {
            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    severity = Severity.INFO,
                    title = "Profile '${profile.label}' is selected but not applied",
                    subject = profile.label,
                    detail = "Applying it would set a ${profile.vendorOui.ifBlank { "locally-administered" }} " +
                        "MAC, hostname ${profile.hostnamePrefix}…, TTL ${profile.initialTtl} and " +
                        "window ${profile.tcpWindow}. All of that requires root — run the Tier 1 " +
                        "identity module on a rooted device.",
                ),
            )
            "Identity reported. Profile '${profile.label}' needs Tier 1 to take effect."
        }

        return ModuleOutcome.Completed(summary)
    }

    /** Default Android device names carry the owner's name far more often than not. */
    private fun looksPersonal(name: String): Boolean =
        name.contains("'") || name.split(' ', '-', '_').size > 1
}
