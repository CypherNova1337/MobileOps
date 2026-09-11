package dev.cyphernova.mobileops.core.beacon

/**
 * Maps the vendor half of a MAC address to a manufacturer.
 *
 * The first three octets of a BSSID are an IEEE-assigned block, so an AP names its maker in
 * every beacon whether or not anyone is associated with it. That makes vendor identification a
 * pure off-network capability, and it is usually the first thing worth knowing about an AP you
 * have not touched.
 *
 * Deliberately partial. The full IEEE registry is tens of thousands of entries and most of them
 * are irrelevant to WiFi infrastructure; this covers the equipment that actually turns up in a
 * survey, and anything else is reported as unknown rather than guessed at.
 */
object OuiLookup {

    /** Vendor for a BSSID, or null when the prefix is not in the table. */
    fun vendorOf(bssid: String): String? {
        val prefix = bssid.replace(":", "").replace("-", "").uppercase().take(6)
        if (prefix.length < 6) return null
        return VENDORS[prefix]
    }

    /**
     * A locally-administered address has bit 1 of the first octet set. Those belong to no
     * vendor by definition — a randomised or deliberately spoofed MAC — which is itself worth
     * noticing on an access point, where randomisation is not normal behaviour.
     */
    fun isLocallyAdministered(bssid: String): Boolean {
        val first = bssid.replace(":", "").replace("-", "").take(2)
        val value = first.toIntOrNull(16) ?: return false
        return value and 0x02 != 0
    }

    fun describe(bssid: String): String = when {
        isLocallyAdministered(bssid) -> "locally administered (randomised or spoofed)"
        else -> vendorOf(bssid) ?: "unknown vendor"
    }

    private val VENDORS: Map<String, String> = mapOf(
        // Consumer router and AP vendors — the bulk of what a residential survey sees.
        "80CC9C" to "Netgear",
        "204E7F" to "Netgear",
        "00146C" to "Netgear",
        "A040A0" to "Netgear",
        "9C3DCF" to "Netgear",
        "50C7BF" to "TP-Link",
        "14CC20" to "TP-Link",
        "EC086B" to "TP-Link",
        "A42BB0" to "TP-Link",
        "001F C6".replace(" ", "") to "ASUS",
        "AC9E17" to "ASUS",
        "2C56DC" to "ASUS",
        "001B11" to "D-Link",
        "C8BE19" to "D-Link",
        "78542E" to "D-Link",
        "000C41" to "Linksys",
        "001839" to "Cisco",
        "001AA1" to "Cisco",
        // Mesh and ISP-supplied equipment.
        "F8BBBF" to "eero",
        "60B4F7" to "eero",
        "001DD3" to "Arris",
        "3C7A8A" to "Arris",
        "B077AC" to "Arris",
        "001AC3" to "Technicolor",
        "C005C2" to "Technicolor",
        // Enterprise.
        "24A43C" to "Ubiquiti",
        "0418D6" to "Ubiquiti",
        "788A20" to "Ubiquiti",
        "DC9FDB" to "Ubiquiti",
        "FCECDA" to "Ubiquiti",
        // Platform vendors, which turn up as hotspots and casting targets.
        "A483E7" to "Apple",
        "F01898" to "Apple",
        "3C15C2" to "Apple",
        "ACBC32" to "Apple",
        "3C5AB4" to "Google",
        "546009" to "Google",
        "F4F5E8" to "Google",
        "44650D" to "Amazon",
        "F0272D" to "Amazon",
        "6837E9" to "Amazon",
        // IoT, which is where the weak security usually lives.
        "240AC4" to "Espressif (IoT)",
        "30AEA4" to "Espressif (IoT)",
        "7C9EBD" to "Espressif (IoT)",
        "84F3EB" to "Espressif (IoT)",
        "B827EB" to "Raspberry Pi",
        "DCA632" to "Raspberry Pi",
        "E45F01" to "Raspberry Pi",
    )
}
