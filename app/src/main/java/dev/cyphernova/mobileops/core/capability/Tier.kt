package dev.cyphernova.mobileops.core.capability

/**
 * Capability tiers, ordered by how much of the radio stack the device will let us reach.
 *
 * The split is not cosmetic: since Android 10 the platform refuses to hand an app the WiFi
 * chipset in monitor mode, so anything that needs raw 802.11 frames is unreachable on a stock
 * device no matter how the app is written. Modules declare the tier they need and the runtime
 * refuses to pretend.
 */
enum class Tier(val level: Int, val label: String, val blurb: String) {
    /** Stock, unrooted, no extra hardware. Managed-mode scanning and IP-layer work only. */
    T0_STOCK(
        level = 0,
        label = "Tier 0 — Stock",
        blurb = "Managed-mode scanning, IP/transport-layer recon, on-device traffic analysis.",
    ),

    /** Root shell available: raw sockets, tcpdump on wlan0, iptables, arbitrary binaries. */
    T1_ROOT(
        level = 1,
        label = "Tier 1 — Root",
        blurb = "Raw sockets, on-interface capture, firewall manipulation, bundled binaries.",
    ),

    /** Monitor-mode-capable radio: patched kernel (nexmon) or an external OTG adapter. */
    T2_MONITOR(
        level = 2,
        label = "Tier 2 — Monitor",
        blurb = "Raw 802.11 frame capture and injection via patched kernel or OTG adapter.",
    ),
    ;

    /** True when a device offering [available] can run something that requires this tier. */
    fun satisfiedBy(available: Tier): Boolean = available.level >= level
}
