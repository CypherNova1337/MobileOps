package dev.cyphernova.mobileops.core.ble

/**
 * Bluetooth SIG company identifiers, which appear at the front of every manufacturer-data
 * advertisement.
 *
 * A BLE device names its maker in the clear, continuously, to anything listening — no pairing,
 * no connection, no network. That makes it the richest passive reconnaissance surface available
 * to a handset, and often the only one that reveals what is physically present in a building.
 *
 * Partial by design, same as the WiFi OUI table: the registry runs to thousands of entries and
 * an unlisted identifier is reported by number rather than guessed at.
 */
object BleVendors {

    fun vendorOf(companyId: Int): String? = COMPANIES[companyId]

    fun describe(companyId: Int): String =
        COMPANIES[companyId] ?: "company 0x%04X (unlisted)".format(companyId)

    /**
     * Apple's Find My advertisements carry type 0x12 inside their manufacturer data. Any item in
     * that network — AirTag, or anything else using it — beacons this continuously, so a survey
     * can spot a tracker that nobody in the room knows about.
     */
    fun isFindMyAdvertisement(companyId: Int, data: ByteArray): Boolean =
        companyId == APPLE && data.isNotEmpty() && (data[0].toInt() and 0xFF) == FIND_MY_TYPE

    /** Apple's continuity protocol — handoff, AirDrop, nearby actions — is type 0x0C and friends. */
    fun isAppleContinuity(companyId: Int, data: ByteArray): Boolean =
        companyId == APPLE && data.isNotEmpty() && (data[0].toInt() and 0xFF) in CONTINUITY_TYPES

    const val APPLE = 0x004C
    private const val FIND_MY_TYPE = 0x12
    private val CONTINUITY_TYPES = setOf(0x02, 0x05, 0x07, 0x08, 0x09, 0x0C, 0x10)

    private val COMPANIES: Map<Int, String> = mapOf(
        0x0001 to "Nokia",
        0x0002 to "Intel",
        0x0003 to "IBM",
        0x0006 to "Microsoft",
        0x000D to "Texas Instruments",
        0x000F to "Broadcom",
        0x004C to "Apple",
        0x0059 to "Nordic Semiconductor",
        0x0075 to "Samsung",
        0x0087 to "Garmin",
        0x00E0 to "Google",
        0x012D to "Sony",
        0x02E5 to "Espressif",
        0x038F to "Xiaomi",
        0x000A to "Cambridge Silicon Radio (Qualcomm)",
        0x001D to "Qualcomm",
        0x0030 to "STMicroelectronics",
        0x0047 to "Harman International",
        0x005D to "Realtek",
        0x00C4 to "LG Electronics",
        0x00D2 to "Dialog Semiconductor",
        0x0131 to "Cypress Semiconductor",
        0x0157 to "Anhui Huami",
        0x0171 to "Amazon",
        0x02FF to "Silicon Laboratories",
        0x0499 to "Ruuvi Innovations",
    )
}

/**
 * Resolves the service UUIDs a BLE device advertises into what they actually are.
 *
 * A device announces its services before anything connects to it, so this is free reconnaissance
 * — and it is far more informative than the raw 128-bit strings. A device offering Human
 * Interface Device is a keyboard or a mouse; one offering a firmware update service will, on
 * plenty of hardware, accept an image from anyone who asks.
 *
 * Bluetooth SIG numbers short services as 16 bits and expands them into a 128-bit base UUID, so
 * the interesting part is always the third through sixth hex digits of the string.
 */
object BleServices {

    /** The four hex digits that carry the meaning, or null when the UUID is a custom one. */
    fun shortIdOf(uuid: String): Int? {
        val normalised = uuid.lowercase()
        if (!normalised.endsWith(BASE_SUFFIX)) return null
        return normalised.take(8).removePrefix("0000").toIntOrNull(16)
    }

    fun describe(uuid: String): String {
        val short = shortIdOf(uuid) ?: return "custom service ${uuid.take(8)}"
        return SERVICES[short] ?: "service 0x%04X".format(short)
    }

    fun describeAll(uuids: List<String>): String = uuids.joinToString(transform = ::describe)

    /**
     * Services worth a second look, with the reason.
     *
     * Advertising one of these is not a vulnerability by itself. It is a statement about what the
     * device will do for whoever connects, which is the thing a survey is trying to establish.
     */
    fun notable(uuid: String): String? = shortIdOf(uuid)?.let(NOTABLE::get)

    private const val BASE_SUFFIX = "-0000-1000-8000-00805f9b34fb"

    private val SERVICES: Map<Int, String> = mapOf(
        0x1800 to "Generic Access",
        0x1801 to "Generic Attribute",
        0x1802 to "Immediate Alert",
        0x1803 to "Link Loss",
        0x1804 to "TX Power",
        0x1805 to "Current Time",
        0x1808 to "Glucose",
        0x1809 to "Health Thermometer",
        0x180A to "Device Information",
        0x180D to "Heart Rate",
        0x180F to "Battery",
        0x1810 to "Blood Pressure",
        0x1811 to "Alert Notification",
        0x1812 to "Human Interface Device",
        0x1813 to "Scan Parameters",
        0x1814 to "Running Speed and Cadence",
        0x1815 to "Automation IO",
        0x1816 to "Cycling Speed and Cadence",
        0x1818 to "Cycling Power",
        0x1819 to "Location and Navigation",
        0x181A to "Environmental Sensing",
        0x181D to "Weight Scale",
        0x1820 to "Internet Protocol Support",
        0x1821 to "Indoor Positioning",
        0x1822 to "Pulse Oximeter",
        0x1823 to "HTTP Proxy",
        0x1825 to "Object Transfer",
        0x1826 to "Fitness Machine",
        0x1827 to "Mesh Provisioning",
        0x1828 to "Mesh Proxy",
        0xFD6F to "Exposure Notification",
        0xFE2C to "Google Fast Pair",
        0xFE59 to "Nordic firmware update (DFU)",
        0xFE95 to "Xiaomi",
        0xFE9F to "Google",
        0xFEAA to "Eddystone beacon",
        0xFEB9 to "LG Electronics",
    )

    private val NOTABLE: Map<Int, String> = mapOf(
        0xFE59 to "a firmware update service, which on a great deal of hardware accepts an image " +
            "from any unauthenticated peer",
        0x1812 to "a Human Interface Device service — a keyboard, mouse or similar input device, " +
            "which is an input path into whatever it is paired with",
        0x1825 to "an object transfer service, which moves files rather than sensor readings",
        0x1827 to "an unprovisioned Bluetooth Mesh node, which is waiting to be claimed by any " +
            "provisioner that reaches it first",
        0x1823 to "an HTTP proxy service, which will make requests on a caller's behalf",
    )
}
