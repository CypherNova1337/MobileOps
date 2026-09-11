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
    )
}
