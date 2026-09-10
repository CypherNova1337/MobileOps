package dev.cyphernova.mobileops.modules.tier1

import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule

/**
 * Applies the selected identity profile to the radio: MAC address, DHCP hostname, and the TTL
 * on outbound packets.
 *
 * This exists to test identity-based access controls — MAC allow-lists, NAC device profiling,
 * and the "printers are exempt" rule that so often turns out to be the way in. If a network
 * admits a handset because it presents an HP OUI and a printer-shaped hostname, that is a
 * finding about the network, and demonstrating it is the job.
 *
 * Everything here needs root, because every one of these knobs is one Android has deliberately
 * taken away from apps.
 */
class IdentitySpoofModule : PentestModule {
    override val id = "t1.identity.spoof"
    override val title = "Apply identity profile"
    override val description =
        "Sets the WiFi MAC, DHCP hostname and outbound TTL to match the selected device profile, " +
            "for testing MAC filtering and NAC device policies. Requires root."
    override val requiredTier = Tier.T1_ROOT
    override val intrusiveness = Intrusiveness.ACTIVE

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val profile = context.profile
        if (profile.id == "passthrough") {
            return ModuleOutcome.Blocked(
                "No profile selected. Pick one on the Device tab before applying an identity.",
            )
        }

        val iface = context.capabilities.wifiInterfaces.firstOrNull { it.startsWith("wlan") }
            ?: return ModuleOutcome.Failed("No wlan interface visible under /sys/class/net.")

        val applied = mutableListOf<String>()
        val failed = mutableListOf<String>()

        val before = RootShell.exec("cat /sys/class/net/$iface/address").stdout.trim()
        val mac = profile.generateMac()

        // The interface has to be down to take a new address; most drivers reject the write
        // outright while it is up, and a few reject it regardless.
        val macResult = RootShell.exec(
            "ip link set $iface down && " +
                "ip link set $iface address $mac && " +
                "ip link set $iface up",
            timeoutMs = 20_000,
        )

        val after = RootShell.exec("cat /sys/class/net/$iface/address").stdout.trim()
        val macApplied = after.equals(mac, ignoreCase = true)

        if (macApplied) {
            applied += "MAC $before → $mac"
        } else {
            // Fall back to the busybox-era command; some vendor kernels only honour this one.
            val fallback = RootShell.exec("ifconfig $iface hw ether $mac", timeoutMs = 15_000)
            val retry = RootShell.exec("cat /sys/class/net/$iface/address").stdout.trim()
            if (retry.equals(mac, ignoreCase = true)) {
                applied += "MAC $before → $mac (via ifconfig)"
            } else {
                failed += "MAC unchanged — the driver refused the write. " +
                    (macResult.stdout.ifBlank { fallback.stdout }).take(120)
            }
        }

        val hostname = profile.generateHostname()
        val hostnameResult = RootShell.exec("settings put global device_name \"$hostname\"")
        if (hostnameResult.ok) applied += "hostname → $hostname" else failed += "hostname unchanged"

        // The TTL target is not compiled into every Android iptables build, so a failure here is
        // expected rather than exceptional.
        val ttlResult = RootShell.exec(
            "iptables -t mangle -F MOBILEOPS_TTL 2>/dev/null; " +
                "iptables -t mangle -A POSTROUTING -o $iface -j TTL --ttl-set ${profile.initialTtl}",
            timeoutMs = 15_000,
        )
        if (ttlResult.ok) {
            applied += "TTL → ${profile.initialTtl}"
        } else {
            failed += "TTL unchanged — this kernel's iptables has no TTL target"
        }

        emit(
            Finding(
                moduleId = id,
                observedAtEpochMs = System.currentTimeMillis(),
                severity = if (failed.isEmpty()) Severity.INFO else Severity.LOW,
                title = "Identity profile '${profile.label}' applied",
                subject = iface,
                detail = buildString {
                    append("Applied: ${applied.joinToString("; ").ifBlank { "nothing" }}. ")
                    if (failed.isNotEmpty()) append("Failed: ${failed.joinToString("; ")}. ")
                    append(
                        "Reconnect to the network for the new identity to be used — an existing " +
                            "association keeps the old address and lease.",
                    )
                },
                data = mapOf(
                    "interface" to iface,
                    "profile" to profile.id,
                    "mac_before" to before,
                    "mac_after" to (if (macApplied) mac else before),
                    "hostname" to hostname,
                    "ttl" to profile.initialTtl.toString(),
                ),
            ),
        )

        return if (applied.isEmpty()) {
            ModuleOutcome.Failed("Nothing could be applied: ${failed.joinToString("; ")}")
        } else {
            ModuleOutcome.Completed(
                "${applied.size} attribute(s) applied" +
                    if (failed.isEmpty()) "." else ", ${failed.size} refused by the platform.",
            )
        }
    }
}
