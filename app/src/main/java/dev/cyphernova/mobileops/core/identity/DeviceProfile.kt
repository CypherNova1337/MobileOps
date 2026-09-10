package dev.cyphernova.mobileops.core.identity

import kotlin.random.Random

/**
 * A device identity to present to the network under test.
 *
 * The point is testing identity-based controls: MAC filtering, NAC device profiling, and
 * "corporate laptops only" policies that are enforced by fingerprint rather than by credential.
 * If a network lets a handset on because it claims an Intel OUI and a Windows TTL, that is the
 * finding.
 *
 * Which of these fields can actually be applied depends on the tier — see [IdentityProbe] for
 * what a stock device will and will not let an app change.
 */
data class DeviceProfile(
    val id: String,
    val label: String,
    val description: String,
    /** Vendor prefix used when generating a spoofed MAC. Empty means fully random. */
    val vendorOui: String,
    val hostnamePrefix: String,
    /** Initial TTL — the strongest single passive-fingerprint signal there is. */
    val initialTtl: Int,
    /** Advertised TCP receive window, the usual secondary signal. */
    val tcpWindow: Int,
    val userAgent: String,
) {
    /**
     * A MAC in this profile's vendor range, with a random 24-bit tail.
     *
     * When no OUI is set, the locally-administered bit is set and the multicast bit cleared,
     * which is the correct shape for an address that belongs to no vendor — the same thing
     * Android's own MAC randomisation produces.
     */
    fun generateMac(random: Random = Random.Default): String {
        val tail = (0 until 3).map { random.nextInt(256) }
        return if (vendorOui.isBlank()) {
            val first = (random.nextInt(256) and 0xFC) or 0x02
            (listOf(first, random.nextInt(256), random.nextInt(256)) + tail)
                .joinToString(":") { "%02X".format(it) }
        } else {
            vendorOui.uppercase() + ":" + tail.joinToString(":") { "%02X".format(it) }
        }
    }

    fun generateHostname(random: Random = Random.Default): String {
        val suffix = (1..6).map { HOSTNAME_ALPHABET.random(random) }.joinToString("")
        return "$hostnamePrefix$suffix"
    }

    private companion object {
        const val HOSTNAME_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    }
}

object DeviceProfiles {

    /** Present the device as it really is — nothing rewritten. */
    val PASSTHROUGH = DeviceProfile(
        id = "passthrough",
        label = "No spoofing",
        description = "Present this device as itself. Android still randomises the WiFi MAC per " +
            "network on its own; see the identity audit for what that means.",
        vendorOui = "",
        hostnamePrefix = "",
        initialTtl = 64,
        tcpWindow = 65535,
        userAgent = "",
    )

    val builtIn: List<DeviceProfile> = listOf(
        PASSTHROUGH,
        DeviceProfile(
            id = "win11-laptop",
            label = "Windows 11 laptop",
            description = "Intel NIC, TTL 128, Edge on Windows. The profile most corporate NAC " +
                "policies are written around.",
            vendorOui = "8C:16:45",
            hostnamePrefix = "DESKTOP-",
            initialTtl = 128,
            tcpWindow = 64240,
            userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
                "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
        ),
        DeviceProfile(
            id = "macbook",
            label = "MacBook",
            description = "Apple NIC, TTL 64, Safari on macOS.",
            vendorOui = "A4:83:E7",
            hostnamePrefix = "MacBook-Pro-",
            initialTtl = 64,
            tcpWindow = 65535,
            userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 " +
                "(KHTML, like Gecko) Version/18.1 Safari/605.1.15",
        ),
        DeviceProfile(
            id = "linux-workstation",
            label = "Linux workstation",
            description = "Intel NIC, TTL 64, Firefox on Linux.",
            vendorOui = "00:1B:21",
            hostnamePrefix = "ws-",
            initialTtl = 64,
            tcpWindow = 64240,
            userAgent = "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
        ),
        DeviceProfile(
            id = "network-printer",
            label = "Network printer",
            description = "HP NIC and a printer-shaped hostname. Useful because printers are " +
                "routinely exempted from the controls everything else has to satisfy.",
            vendorOui = "3C:D9:2B",
            hostnamePrefix = "HPLJ-",
            initialTtl = 64,
            tcpWindow = 29200,
            userAgent = "",
        ),
        DeviceProfile(
            id = "raspberry-pi",
            label = "Raspberry Pi",
            description = "Raspberry Pi Foundation NIC — a plausible unmanaged device on a flat " +
                "network.",
            vendorOui = "B8:27:EB",
            hostnamePrefix = "raspberrypi-",
            initialTtl = 64,
            tcpWindow = 64240,
            userAgent = "curl/8.9.1",
        ),
        DeviceProfile(
            id = "anonymous",
            label = "Anonymous / random",
            description = "Fully random locally-administered MAC belonging to no vendor, and a " +
                "neutral hostname.",
            vendorOui = "",
            hostnamePrefix = "android-",
            initialTtl = 64,
            tcpWindow = 65535,
            userAgent = "",
        ),
    )

    fun byId(id: String): DeviceProfile = builtIn.firstOrNull { it.id == id } ?: PASSTHROUGH
}
