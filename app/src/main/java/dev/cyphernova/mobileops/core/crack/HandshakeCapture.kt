package dev.cyphernova.mobileops.core.crack

/**
 * A captured WPA2 authentication attempt, reduced to the values a guess is tested against.
 *
 * There are two shapes, and the difference matters operationally rather than cryptographically.
 * A [Eapol] handshake needs a real client to have authenticated while someone was listening; a
 * [Pmkid] needs only the AP's first response to an association request, so it can be collected
 * at three in the morning with nobody else present. Both verify a passphrase the same way once
 * they exist.
 */
sealed interface HandshakeCapture {

    val ssid: String
    val apMac: ByteArray
    val staMac: ByteArray

    /** A four-way handshake, verified by recomputing the MIC over the EAPOL frame. */
    data class Eapol(
        override val ssid: String,
        override val apMac: ByteArray,
        override val staMac: ByteArray,
        val aNonce: ByteArray,
        val sNonce: ByteArray,
        val mic: ByteArray,
        /** The frame with its MIC field already zeroed, which is what gets signed. */
        val eapolFrame: ByteArray,
        val keyDescriptorVersion: Int,
    ) : HandshakeCapture

    /** A PMKID, verified directly from the PMK with no handshake involved. */
    data class Pmkid(
        override val ssid: String,
        override val apMac: ByteArray,
        override val staMac: ByteArray,
        val pmkid: ByteArray,
    ) : HandshakeCapture

    val label: String
        get() = when (this) {
            is Eapol -> "EAPOL handshake"
            is Pmkid -> "PMKID"
        }
}

/**
 * Reads the two capture formats that offline WiFi tooling actually exchanges.
 *
 * Neither is a packet capture. A stock handset cannot put its radio into monitor mode, so it
 * cannot collect either of these itself — they come from an adapter that can, and arrive here as
 * a file. That division is the honest one: the phone does the part that is pure computation, and
 * the radio work happens on hardware that can do it.
 *
 * Every parser is total. A malformed line is skipped rather than thrown, because these files are
 * routinely hand-edited and half-written by tools that were interrupted.
 */
object CaptureFormats {

    /**
     * hashcat's 22000 format, which is what current tooling emits.
     *
     * One record per line, asterisk-separated:
     * `WPA*01*PMKID*apmac*stamac*essid***` for a PMKID, and
     * `WPA*02*mic*apmac*stamac*essid*anonce*eapol*messagepair` for a handshake.
     */
    fun parse22000(text: String): List<HandshakeCapture> =
        text.lineSequence().mapNotNull(::parse22000Line).toList()

    private fun parse22000Line(line: String): HandshakeCapture? {
        val trimmed = line.trim()
        if (!trimmed.startsWith("WPA*")) return null
        val fields = trimmed.split('*')
        if (fields.size < 6) return null

        val apMac = hex(fields[3]) ?: return null
        val staMac = hex(fields[4]) ?: return null
        if (apMac.size != MAC_BYTES || staMac.size != MAC_BYTES) return null
        // The SSID is hex-encoded precisely because it can contain anything, separators included.
        val ssid = hex(fields[5])?.toString(Charsets.UTF_8) ?: return null

        return when (fields[1]) {
            "01" -> {
                val pmkid = hex(fields[2]) ?: return null
                if (pmkid.size != PMKID_BYTES) return null
                HandshakeCapture.Pmkid(ssid, apMac, staMac, pmkid)
            }

            "02" -> {
                if (fields.size < 9) return null
                val mic = hex(fields[2]) ?: return null
                val aNonce = hex(fields[6]) ?: return null
                val eapol = hex(fields[7]) ?: return null
                eapolHandshake(ssid, apMac, staMac, aNonce, mic, eapol)
            }

            else -> null
        }
    }

    /**
     * The older hccapx format: fixed 393-byte records, little-endian, with the fields at known
     * offsets. Still what a lot of existing captures are stored as.
     */
    fun parseHccapx(bytes: ByteArray): List<HandshakeCapture> {
        val records = mutableListOf<HandshakeCapture>()
        var offset = 0
        while (offset + HCCAPX_RECORD <= bytes.size) {
            parseHccapxRecord(bytes, offset)?.let(records::add)
            offset += HCCAPX_RECORD
        }
        return records
    }

    private fun parseHccapxRecord(bytes: ByteArray, base: Int): HandshakeCapture? {
        if (bytes[base] != 'H'.code.toByte() || bytes[base + 1] != 'C'.code.toByte() ||
            bytes[base + 2] != 'P'.code.toByte() || bytes[base + 3] != 'X'.code.toByte()
        ) {
            return null
        }

        val ssidLength = bytes[base + 9].toInt() and 0xFF
        if (ssidLength > SSID_MAX) return null
        val ssid = String(bytes, base + 10, ssidLength, Charsets.UTF_8)

        val keyVersion = bytes[base + 42].toInt() and 0xFF
        val mic = bytes.copyOfRange(base + 43, base + 59)
        val apMac = bytes.copyOfRange(base + 59, base + 65)
        val aNonce = bytes.copyOfRange(base + 65, base + 97)
        val staMac = bytes.copyOfRange(base + 97, base + 103)
        val sNonce = bytes.copyOfRange(base + 103, base + 135)

        val eapolLength = (bytes[base + 135].toInt() and 0xFF) or
            ((bytes[base + 136].toInt() and 0xFF) shl 8)
        if (eapolLength !in 1..EAPOL_MAX) return null
        val eapol = bytes.copyOfRange(base + 137, base + 137 + eapolLength)

        return HandshakeCapture.Eapol(
            ssid = ssid,
            apMac = apMac,
            staMac = staMac,
            aNonce = aNonce,
            // hccapx stores the SNonce separately rather than making the reader dig it out of
            // the frame, so it is taken from the record where 22000 takes it from the EAPOL.
            sNonce = sNonce,
            mic = mic,
            eapolFrame = zeroMic(eapol),
            keyDescriptorVersion = keyVersion,
        )
    }

    /**
     * Builds a handshake from an EAPOL frame, reading the fields the format leaves implicit.
     *
     * The SNonce and the key descriptor version are both inside the frame rather than alongside
     * it. Taking the version from the wrong place is the usual reason a correct passphrase looks
     * wrong: the MIC would then be recomputed with the wrong algorithm every time.
     */
    fun eapolHandshake(
        ssid: String,
        apMac: ByteArray,
        staMac: ByteArray,
        aNonce: ByteArray,
        mic: ByteArray,
        eapol: ByteArray,
    ): HandshakeCapture.Eapol? {
        if (eapol.size < EAPOL_MIN || aNonce.size != NONCE_BYTES || mic.size != MIC_BYTES) return null
        val keyInfo = ((eapol[KEY_INFO_OFFSET].toInt() and 0xFF) shl 8) or
            (eapol[KEY_INFO_OFFSET + 1].toInt() and 0xFF)
        return HandshakeCapture.Eapol(
            ssid = ssid,
            apMac = apMac,
            staMac = staMac,
            aNonce = aNonce,
            sNonce = eapol.copyOfRange(NONCE_OFFSET, NONCE_OFFSET + NONCE_BYTES),
            mic = mic,
            eapolFrame = zeroMic(eapol),
            keyDescriptorVersion = keyInfo and KEY_DESCRIPTOR_VERSION_MASK,
        )
    }

    /** The MIC cannot sign itself, so the field is zeroed before the frame is hashed. */
    private fun zeroMic(eapol: ByteArray): ByteArray {
        if (eapol.size < MIC_OFFSET + MIC_BYTES) return eapol
        val copy = eapol.copyOf()
        java.util.Arrays.fill(copy, MIC_OFFSET, MIC_OFFSET + MIC_BYTES, 0)
        return copy
    }

    fun hex(value: String): ByteArray? {
        val cleaned = value.trim()
        if (cleaned.isEmpty() || cleaned.length % 2 != 0) return null
        return runCatching {
            ByteArray(cleaned.length / 2) { index ->
                cleaned.substring(index * 2, index * 2 + 2).toInt(16).toByte()
            }
        }.getOrNull()
    }

    private const val MAC_BYTES = 6
    private const val NONCE_BYTES = 32
    private const val MIC_BYTES = 16
    private const val PMKID_BYTES = 16
    private const val SSID_MAX = 32
    private const val EAPOL_MAX = 256
    private const val HCCAPX_RECORD = 393

    /**
     * Offsets into an EAPOL-Key frame counted from the 802.1X version byte: key information at 5,
     * the nonce at 17 and the MIC at 81.
     */
    private const val KEY_INFO_OFFSET = 5
    private const val NONCE_OFFSET = 17
    private const val MIC_OFFSET = 81
    private const val EAPOL_MIN = 99
    private const val KEY_DESCRIPTOR_VERSION_MASK = 0x07
}
