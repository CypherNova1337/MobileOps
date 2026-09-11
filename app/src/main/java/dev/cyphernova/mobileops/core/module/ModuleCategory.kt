package dev.cyphernova.mobileops.core.module

/**
 * How modules are grouped in the UI.
 *
 * The order is the order an engagement actually runs in — survey the air, map the network, look
 * at traffic, then test what was found — so the list doubles as a rough methodology rather than
 * being sorted alphabetically or by tier. Tier-gated modules sit together at the end because on
 * most devices none of them can run, and burying a locked module among usable ones wastes the
 * reader's attention.
 */
enum class ModuleCategory(val label: String, val blurb: String) {
    WIRELESS(
        label = "Wireless",
        blurb = "WiFi in the air around you. Needs no network of any kind.",
    ),
    RADIO(
        label = "Other radios",
        blurb = "Cellular, Bluetooth and ranging. Works where there is no WiFi at all.",
    ),
    NETWORK(
        label = "Network discovery",
        blurb = "What is on the subnet you are attached to.",
    ),
    TRAFFIC(
        label = "Traffic",
        blurb = "Capture and inspect what this device sends.",
    ),
    EXPLOIT(
        label = "Exploitation",
        blurb = "Test whether what was found is actually reachable.",
    ),
    DEVICE(
        label = "This device",
        blurb = "What the handset itself gives away.",
    ),
    PRIVILEGED(
        label = "Root & monitor mode",
        blurb = "Requires root or a monitor-capable radio.",
    ),
}
