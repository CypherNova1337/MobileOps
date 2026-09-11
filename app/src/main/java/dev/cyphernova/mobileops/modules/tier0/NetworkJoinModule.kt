package dev.cyphernova.mobileops.modules.tier0

import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleCategory
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule
import dev.cyphernova.mobileops.core.net.NetworkJoin

/**
 * Joins a selected WiFi network so the LAN modules can run against it.
 *
 * This is the hinge between passive survey and active testing. Everything in the Wireless section
 * works from outside a network; everything in Network discovery needs to be on one. Rather than
 * making the operator leave the app, change the phone's WiFi, and come back, this takes a
 * per-app association: the handset keeps whatever connection it had, and only this app's sockets
 * move to the target.
 *
 * Run it again to drop the association.
 */
class NetworkJoinModule : PentestModule {
    override val id = "t0.wifi.join"
    override val title = "Join target network"
    override val description =
        "Associates this app with the selected WiFi network without changing the phone's own " +
            "connection, so LAN modules can run against it. Run again to disconnect."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.ACTIVE
    override val category = ModuleCategory.WIRELESS

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val join = NetworkJoin(context.androidContext)

        if (NetworkJoin.isJoined) {
            val previous = NetworkJoin.status.value.ssid
            join.release()
            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    severity = Severity.INFO,
                    title = "Left ${previous ?: "the network"}",
                    subject = previous ?: "network",
                    detail = "The per-app association was dropped and this app's traffic has gone " +
                        "back to the device's normal routing.",
                ),
            )
            return ModuleOutcome.Completed("Disconnected from ${previous ?: "the network"}.")
        }

        if (!join.supported) {
            return ModuleOutcome.Blocked(
                "Per-app WiFi association needs Android 10 or later. Join the network through " +
                    "system settings instead.",
            )
        }

        val networks = context.targets.networks()
        val network = when {
            networks.isEmpty() -> return ModuleOutcome.Blocked(
                "No network selected. Pick exactly one on the Targets tab.",
            )
            networks.size > 1 -> return ModuleOutcome.Blocked(
                "${networks.size} networks selected. Pick exactly one to join.",
            )
            else -> networks.single()
        }

        if (network.ssid.isBlank()) {
            return ModuleOutcome.Blocked(
                "That network hides its SSID, which cannot be joined by name. Enter it by hand in " +
                    "system settings.",
            )
        }

        val failure = join.join(network.ssid)
        if (failure != null) {
            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    severity = Severity.INFO,
                    title = "Could not join ${network.ssid}",
                    subject = network.ssid,
                    detail = "$failure A wrong passphrase, a refused dialog and an AP that simply " +
                        "will not accept the association all present the same way here.",
                ),
            )
            return ModuleOutcome.Failed(failure)
        }

        val status = NetworkJoin.status.value
        val position = LocalNetwork.position(context.androidContext)

        emit(
            Finding(
                moduleId = id,
                observedAtEpochMs = System.currentTimeMillis(),
                // Joining is a finding in itself: it establishes that these credentials, or none
                // at all, are enough to get onto the network.
                severity = Severity.INFO,
                title = "Joined ${network.ssid}",
                subject = network.ssid,
                detail = buildString {
                    append(status.detail)
                    position?.let {
                        append(" Address ${it.localAddress}/${it.prefixLength} on ${it.interfaceName}, ")
                        append("gateway ${it.gateway ?: "unknown"}.")
                    }
                    append(" The LAN modules will now run against this network.")
                },
                data = mapOf(
                    "ssid" to network.ssid,
                    "bssid" to network.bssid,
                    "bound" to status.bound.toString(),
                    "local_address" to (position?.localAddress ?: ""),
                    "gateway" to (position?.gateway ?: ""),
                ),
            ),
        )

        return ModuleOutcome.Completed(
            "Joined ${network.ssid}. Run again to disconnect.",
        )
    }
}
