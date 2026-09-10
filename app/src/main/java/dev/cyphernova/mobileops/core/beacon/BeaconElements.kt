package dev.cyphernova.mobileops.core.beacon

/** WPS details advertised in the beacon's vendor element. */
data class WpsInfo(
    /** True once the AP has been configured; false means it is still in its out-of-box state. */
    val configured: Boolean?,
    /**
     * Whether the AP has locked its setup PIN. This is the field that decides whether the
     * offline PIN attack is viable at all, and Android's capability string never carries it.
     */
    val setupLocked: Boolean?,
    val version: String?,
    val manufacturer: String?,
    val modelName: String?,
    val modelNumber: String?,
    val serialNumber: String?,
    val deviceName: String?,
    val devicePasswordId: Int?,
) {
    /** Push-button mode is advertised as password id 4. */
    val pushButtonActive: Boolean get() = devicePasswordId == 0x0004
}

/** The RSN element, which is the authoritative statement of an AP's security. */
data class RsnInfo(
    val groupCipher: String,
    val pairwiseCiphers: List<String>,
    val akmSuites: List<String>,
    val managementFrameProtectionRequired: Boolean,
    val managementFrameProtectionCapable: Boolean,
    val preAuthentication: Boolean,
) {
    val usesSae: Boolean get() = akmSuites.any { it.contains("SAE") }
    val usesPsk: Boolean get() = akmSuites.any { it == "PSK" || it == "PSK-SHA256" || it == "FT-PSK" }
    val usesEnterprise: Boolean get() = akmSuites.any { it.contains("802.1X") }
    val usesOwe: Boolean get() = akmSuites.any { it == "OWE" }

    /** Both SAE and PSK offered on one BSSID: a client can be steered onto the weaker path. */
    val isWpa3Transition: Boolean get() = usesSae && usesPsk

    val hasWeakCipher: Boolean
        get() = (pairwiseCiphers + groupCipher).any { it == "TKIP" || it.startsWith("WEP") }
}

/** Everything worth knowing that the raw elements carry. */
data class BeaconProfile(
    val wps: WpsInfo?,
    val rsn: RsnInfo?,
    val legacyWpaPresent: Boolean,
    val vendorOuis: List<String>,
    val elementIds: List<Int>,
) {
    val supportsHt: Boolean get() = ELEMENT_HT_CAPABILITIES in elementIds
    val supportsVht: Boolean get() = ELEMENT_VHT_CAPABILITIES in elementIds
    val supportsHe: Boolean get() = ELEMENT_EXTENSION in elementIds
}

private const val ELEMENT_HT_CAPABILITIES = 45
private const val ELEMENT_VHT_CAPABILITIES = 191
private const val ELEMENT_EXTENSION = 255

/**
 * Parses 802.11 information elements straight out of a beacon.
 *
 * Android summarises an AP's security into a capability string like `[WPA2-PSK-CCMP][WPS]`, which
 * is enough to say WPS is enabled and nothing more. The elements underneath carry what actually
 * decides whether a weakness is exploitable — whether WPS has locked its PIN, exactly which AKM
 * suites and ciphers are offered, whether 802.11w is required or merely supported — and since
 * API 30 they are readable without root.
 *
 * Every parser here is total: a malformed element returns null rather than throwing, because
 * these bytes come off the air from anything that cares to transmit.
 */
object BeaconElements {

    private const val ELEMENT_RSN = 48
    private const val ELEMENT_VENDOR_SPECIFIC = 221

    private val OUI_MICROSOFT = byteArrayOf(0x00, 0x50, 0xF2.toByte())
    private const val VENDOR_TYPE_WPA = 0x01
    private const val VENDOR_TYPE_WPS = 0x04

    /** @param elements element id paired with its payload, excluding the id and length bytes. */
    fun parse(elements: List<Pair<Int, ByteArray>>): BeaconProfile {
        var wps: WpsInfo? = null
        var rsn: RsnInfo? = null
        var legacyWpa = false
        val ouis = mutableListOf<String>()

        elements.forEach { (id, payload) ->
            when (id) {
                ELEMENT_RSN -> rsn = parseRsn(payload) ?: rsn
                ELEMENT_VENDOR_SPECIFIC -> {
                    if (payload.size < 4) return@forEach
                    val oui = payload.copyOfRange(0, 3)
                    ouis += oui.joinToString(":") { "%02X".format(it) }
                    if (oui.contentEquals(OUI_MICROSOFT)) {
                        when (payload[3].toInt() and 0xFF) {
                            VENDOR_TYPE_WPS -> wps = parseWps(payload.copyOfRange(4, payload.size)) ?: wps
                            VENDOR_TYPE_WPA -> legacyWpa = true
                        }
                    }
                }
            }
        }

        return BeaconProfile(
            wps = wps,
            rsn = rsn,
            legacyWpaPresent = legacyWpa,
            vendorOuis = ouis.distinct(),
            elementIds = elements.map { it.first }.distinct(),
        )
    }

    /**
     * WPS attributes are big-endian type/length/value triples, unlike the little-endian counts in
     * the RSN element — the two formats sit side by side in the same beacon.
     */
    fun parseWps(payload: ByteArray): WpsInfo? {
        var configured: Boolean? = null
        var locked: Boolean? = null
        var version: String? = null
        var manufacturer: String? = null
        var modelName: String? = null
        var modelNumber: String? = null
        var serial: String? = null
        var deviceName: String? = null
        var passwordId: Int? = null

        var index = 0
        var sawAttribute = false
        while (index + 4 <= payload.size) {
            val type = ((payload[index].toInt() and 0xFF) shl 8) or (payload[index + 1].toInt() and 0xFF)
            val length = ((payload[index + 2].toInt() and 0xFF) shl 8) or (payload[index + 3].toInt() and 0xFF)
            index += 4
            if (length < 0 || index + length > payload.size) return if (sawAttribute) {
                WpsInfo(configured, locked, version, manufacturer, modelName, modelNumber, serial, deviceName, passwordId)
            } else {
                null
            }

            val value = payload.copyOfRange(index, index + length)
            index += length
            sawAttribute = true

            when (type) {
                ATTR_WPS_STATE -> configured = value.firstOrNull()?.toInt() == 0x02
                ATTR_AP_SETUP_LOCKED -> locked = value.firstOrNull()?.toInt() == 0x01
                ATTR_VERSION -> version = value.firstOrNull()?.let {
                    val raw = it.toInt() and 0xFF
                    "${raw shr 4}.${raw and 0x0F}"
                }
                ATTR_MANUFACTURER -> manufacturer = value.asText()
                ATTR_MODEL_NAME -> modelName = value.asText()
                ATTR_MODEL_NUMBER -> modelNumber = value.asText()
                ATTR_SERIAL_NUMBER -> serial = value.asText()
                ATTR_DEVICE_NAME -> deviceName = value.asText()
                ATTR_DEVICE_PASSWORD_ID -> if (value.size >= 2) {
                    passwordId = ((value[0].toInt() and 0xFF) shl 8) or (value[1].toInt() and 0xFF)
                }
            }
        }

        return if (sawAttribute) {
            WpsInfo(configured, locked, version, manufacturer, modelName, modelNumber, serial, deviceName, passwordId)
        } else {
            null
        }
    }

    /** RSN counts are little-endian, per 802.11. */
    fun parseRsn(payload: ByteArray): RsnInfo? {
        if (payload.size < 8) return null
        var index = 2 // skip version

        val group = suiteName(payload, index, CIPHERS) ?: return null
        index += 4

        if (index + 2 > payload.size) return null
        val pairwiseCount = le16(payload, index)
        index += 2
        val pairwise = mutableListOf<String>()
        repeat(pairwiseCount) {
            suiteName(payload, index, CIPHERS)?.let { pairwise += it }
            index += 4
        }
        if (index > payload.size) return null

        if (index + 2 > payload.size) {
            return RsnInfo(group, pairwise, emptyList(), false, false, false)
        }
        val akmCount = le16(payload, index)
        index += 2
        val akms = mutableListOf<String>()
        repeat(akmCount) {
            suiteName(payload, index, AKMS)?.let { akms += it }
            index += 4
        }
        if (index > payload.size) return null

        // RSN capabilities are optional; an element that stops here simply offers no 802.11w.
        val capabilities = if (index + 2 <= payload.size) le16(payload, index) else 0

        return RsnInfo(
            groupCipher = group,
            pairwiseCiphers = pairwise,
            akmSuites = akms,
            managementFrameProtectionRequired = capabilities and 0x0040 != 0,
            managementFrameProtectionCapable = capabilities and 0x0080 != 0,
            preAuthentication = capabilities and 0x0001 != 0,
        )
    }

    private fun suiteName(payload: ByteArray, offset: Int, names: Map<Int, String>): String? {
        if (offset + 4 > payload.size) return null
        val type = payload[offset + 3].toInt() and 0xFF
        val oui = payload.copyOfRange(offset, offset + 3)
        // A vendor-defined suite is legal and simply not one of the standard ones.
        if (!oui.contentEquals(OUI_IEEE)) {
            return "vendor-${oui.joinToString("") { "%02X".format(it) }}-$type"
        }
        return names[type] ?: "unknown($type)"
    }

    private fun le16(data: ByteArray, offset: Int): Int =
        (data[offset].toInt() and 0xFF) or ((data[offset + 1].toInt() and 0xFF) shl 8)

    private fun ByteArray.asText(): String? =
        String(this, Charsets.UTF_8).trim().takeIf { text ->
            text.isNotBlank() && text.all { it.code in 0x20..0xFFFF }
        }

    private val OUI_IEEE = byteArrayOf(0x00, 0x0F, 0xAC.toByte())

    private const val ATTR_DEVICE_PASSWORD_ID = 0x1012
    private const val ATTR_MANUFACTURER = 0x1021
    private const val ATTR_MODEL_NAME = 0x1023
    private const val ATTR_MODEL_NUMBER = 0x1024
    private const val ATTR_SERIAL_NUMBER = 0x1042
    private const val ATTR_WPS_STATE = 0x1044
    private const val ATTR_VERSION = 0x104A
    private const val ATTR_AP_SETUP_LOCKED = 0x1057
    private const val ATTR_DEVICE_NAME = 0x1011

    private val CIPHERS = mapOf(
        0 to "use-group",
        1 to "WEP-40",
        2 to "TKIP",
        4 to "CCMP-128",
        5 to "WEP-104",
        6 to "BIP-CMAC-128",
        8 to "GCMP-128",
        9 to "GCMP-256",
        10 to "CCMP-256",
        11 to "BIP-GMAC-128",
        12 to "BIP-GMAC-256",
        13 to "BIP-CMAC-256",
    )

    private val AKMS = mapOf(
        1 to "802.1X",
        2 to "PSK",
        3 to "FT-802.1X",
        4 to "FT-PSK",
        5 to "802.1X-SHA256",
        6 to "PSK-SHA256",
        7 to "TDLS",
        8 to "SAE",
        9 to "FT-SAE",
        11 to "802.1X-SuiteB",
        12 to "802.1X-SuiteB-192",
        13 to "FT-802.1X-SHA384",
        18 to "OWE",
    )
}
