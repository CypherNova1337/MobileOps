package dev.cyphernova.mobileops.core.radio

/**
 * Decodes the Bluetooth Class of Device field, a 24-bit value every discoverable classic device
 * broadcasts alongside its address.
 *
 * The class says what a device *is* — phone, laptop, headset, printer, car kit, wearable — and
 * what it offers, before anything pairs with it or connects. A survey therefore gets a physical
 * inventory of a space for free, which is exactly the kind of thing an off-network engagement
 * is trying to build.
 *
 * Layout, from the Bluetooth assigned-numbers document: bits 0-1 are format, bits 2-7 the minor
 * class, bits 8-12 the major class, bits 13-23 the service classes.
 */
object BluetoothClassDecode {

    data class Decoded(
        val major: String,
        val minor: String,
        val services: List<String>,
    ) {
        val label: String get() = if (minor.isBlank()) major else "$major / $minor"
    }

    fun decode(deviceClass: Int): Decoded {
        val major = (deviceClass shr 8) and 0x1F
        val minor = (deviceClass shr 2) and 0x3F
        return Decoded(
            major = MAJOR[major] ?: "uncategorised (0x%02X)".format(major),
            minor = minorOf(major, minor),
            services = servicesOf(deviceClass),
        )
    }

    /**
     * A device offering audio or telephony will talk to anything that pairs; one offering object
     * transfer or networking is a data path. That distinction is what decides whether a device
     * found in a survey is worth following up.
     */
    fun servicesOf(deviceClass: Int): List<String> = buildList {
        val bits = deviceClass shr 13
        if (bits and 0x001 != 0) add("limited discoverable")
        if (bits and 0x008 != 0) add("positioning")
        if (bits and 0x010 != 0) add("networking")
        if (bits and 0x020 != 0) add("rendering")
        if (bits and 0x040 != 0) add("capture")
        if (bits and 0x080 != 0) add("object transfer")
        if (bits and 0x100 != 0) add("audio")
        if (bits and 0x200 != 0) add("telephony")
        if (bits and 0x400 != 0) add("information")
    }

    /** True where the class advertises a service that moves data rather than only audio. */
    fun carriesData(deviceClass: Int): Boolean {
        val bits = deviceClass shr 13
        return bits and 0x010 != 0 || bits and 0x080 != 0 || bits and 0x400 != 0
    }

    private fun minorOf(major: Int, minor: Int): String = when (major) {
        0x01 -> COMPUTER_MINOR[minor].orEmpty()
        0x02 -> PHONE_MINOR[minor].orEmpty()
        0x04 -> AUDIO_MINOR[minor].orEmpty()
        0x05 -> peripheralMinor(minor)
        0x06 -> IMAGING_MINOR.filterKeys { minor and it != 0 }.values.joinToString("/")
        0x07 -> WEARABLE_MINOR[minor].orEmpty()
        else -> ""
    }

    /**
     * Peripherals split their minor field: the top two bits are the pointing/keyboard flags and
     * the low four are the device type, so a keyboard-and-mouse combo sets both.
     */
    private fun peripheralMinor(minor: Int): String {
        val kind = PERIPHERAL_MINOR[minor and 0x0F].orEmpty()
        val flags = buildList {
            if (minor and 0x10 != 0) add("keyboard")
            if (minor and 0x20 != 0) add("pointing device")
        }
        return (flags + kind).filter { it.isNotBlank() }.joinToString("/")
    }

    private val MAJOR = mapOf(
        0x00 to "miscellaneous",
        0x01 to "computer",
        0x02 to "phone",
        0x03 to "network access point",
        0x04 to "audio/video",
        0x05 to "peripheral",
        0x06 to "imaging",
        0x07 to "wearable",
        0x08 to "toy",
        0x09 to "health",
        0x1F to "unclassified",
    )

    private val COMPUTER_MINOR = mapOf(
        0x01 to "desktop", 0x02 to "server", 0x03 to "laptop",
        0x04 to "handheld", 0x05 to "palm", 0x06 to "wearable computer",
    )

    private val PHONE_MINOR = mapOf(
        0x01 to "cellular", 0x02 to "cordless", 0x03 to "smartphone",
        0x04 to "wired modem", 0x05 to "ISDN",
    )

    private val AUDIO_MINOR = mapOf(
        0x01 to "headset", 0x02 to "hands-free", 0x04 to "microphone",
        0x05 to "loudspeaker", 0x06 to "headphones", 0x07 to "portable audio",
        0x08 to "car audio", 0x09 to "set-top box", 0x0A to "HiFi audio",
        0x0B to "VCR", 0x0C to "video camera", 0x0D to "camcorder",
        0x0E to "video monitor", 0x0F to "video display and loudspeaker",
        0x12 to "gaming/toy",
    )

    private val PERIPHERAL_MINOR = mapOf(
        0x01 to "joystick", 0x02 to "gamepad", 0x03 to "remote control",
        0x04 to "sensor", 0x05 to "digitiser tablet", 0x06 to "card reader",
        0x07 to "digital pen", 0x08 to "barcode scanner",
    )

    private val IMAGING_MINOR = mapOf(
        0x04 to "display", 0x08 to "camera", 0x10 to "scanner", 0x20 to "printer",
    )

    private val WEARABLE_MINOR = mapOf(
        0x01 to "wristwatch", 0x02 to "pager", 0x03 to "jacket",
        0x04 to "helmet", 0x05 to "glasses",
    )
}
