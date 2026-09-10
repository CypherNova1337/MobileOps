package dev.cyphernova.mobileops.core.module

import android.content.Context
import android.content.pm.PackageManager
import androidx.core.content.ContextCompat
import dev.cyphernova.mobileops.core.capability.DeviceCapabilities
import dev.cyphernova.mobileops.core.evidence.EvidenceStore
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.target.TargetSelection

/** Why a module cannot be started right now, or null when it can. */
data class Blocker(val headline: String, val remedy: String)

/**
 * The single door every module run goes through. Checks tier, permissions and target selection
 * before anything touches the network, then files whatever the module emits into the evidence
 * log so a run always leaves a record.
 */
class ModuleRunner(private val evidenceStore: EvidenceStore) {

    /** Pre-flight check, also used by the UI to explain why a module is greyed out. */
    fun blockerFor(
        module: PentestModule,
        context: Context,
        capabilities: DeviceCapabilities,
        targets: TargetSelection,
    ): Blocker? {
        if (!module.requiredTier.satisfiedBy(capabilities.tier)) {
            return Blocker(
                headline = "Needs ${module.requiredTier.label}, device is ${capabilities.tier.label}",
                remedy = module.requiredTier.blurb,
            )
        }
        val missing = module.requiredPermissions.filterNot { permission ->
            ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED
        }
        if (missing.isNotEmpty()) {
            return Blocker(
                headline = "Missing permission${if (missing.size > 1) "s" else ""}",
                remedy = missing.joinToString { it.substringAfterLast('.') },
            )
        }
        if (module.requiresTarget && targets.hosts().isEmpty()) {
            return Blocker(
                headline = "No target selected",
                remedy = "Pick a host on the Targets tab, or run a sweep to discover some.",
            )
        }
        return null
    }

    suspend fun run(
        module: PentestModule,
        context: Context,
        capabilities: DeviceCapabilities,
        targets: TargetSelection,
    ): ModuleOutcome {
        blockerFor(module, context, capabilities, targets)?.let {
            return ModuleOutcome.Blocked("${it.headline}. ${it.remedy}")
        }

        val moduleContext = ModuleContext(
            androidContext = context,
            capabilities = capabilities,
            targets = targets,
        )

        return runCatching {
            module.run(moduleContext) { finding: Finding -> evidenceStore.record(finding) }
        }.getOrElse { error ->
            ModuleOutcome.Failed(error.message ?: error::class.java.simpleName)
        }
    }
}
