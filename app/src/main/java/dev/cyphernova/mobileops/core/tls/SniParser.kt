package dev.cyphernova.mobileops.core.tls

/**
 * Pulls the SNI hostname out of a TLS ClientHello.
 *
 * Interception has to present a certificate before it knows what the client asked for, and the
 * only thing in the handshake that names the intended host is this extension. Without it the
 * best available fallback is the destination IP, which almost never matches the certificate a
 * client expects.
 *
 * Deliberately dependency-free and total: every read is bounds-checked and a malformed record
 * returns null rather than throwing, because this parses the first bytes an untrusted peer sends.
 */
object SniParser {

    private const val HANDSHAKE_RECORD = 0x16
    private const val CLIENT_HELLO = 0x01
    private const val EXTENSION_SERVER_NAME = 0x0000
    private const val NAME_TYPE_HOST = 0x00

    fun extractHostname(data: ByteArray, length: Int = data.size): String? {
        val reader = Reader(data, length)

        // TLSPlaintext: type, legacy_version, length
        if (reader.u8() != HANDSHAKE_RECORD) return null
        reader.skip(2) || return null
        val recordLength = reader.u16() ?: return null
        if (recordLength <= 0) return null

        // Handshake: msg_type, length
        if (reader.u8() != CLIENT_HELLO) return null
        reader.skip(3) || return null

        // client_version, random
        reader.skip(2 + 32) || return null

        // legacy_session_id
        val sessionIdLength = reader.u8() ?: return null
        reader.skip(sessionIdLength) || return null

        // cipher_suites
        val cipherSuitesLength = reader.u16() ?: return null
        reader.skip(cipherSuitesLength) || return null

        // legacy_compression_methods
        val compressionLength = reader.u8() ?: return null
        reader.skip(compressionLength) || return null

        // extensions
        val extensionsLength = reader.u16() ?: return null
        val extensionsEnd = reader.position + extensionsLength

        while (reader.position + 4 <= minOf(extensionsEnd, reader.limit)) {
            val type = reader.u16() ?: return null
            val size = reader.u16() ?: return null
            if (type != EXTENSION_SERVER_NAME) {
                reader.skip(size) || return null
                continue
            }

            // ServerNameList: list length, then entries of (name_type, length, host)
            reader.skip(2) || return null
            val nameType = reader.u8() ?: return null
            if (nameType != NAME_TYPE_HOST) return null
            val hostLength = reader.u16() ?: return null
            val host = reader.bytes(hostLength) ?: return null

            return String(host, Charsets.US_ASCII)
                .takeIf { it.isNotBlank() && it.all { c -> c.code in 0x20..0x7E } }
        }
        return null
    }

    /** Cheap check for whether a byte stream looks like the start of a TLS handshake at all. */
    fun looksLikeTls(data: ByteArray, length: Int = data.size): Boolean =
        length >= 3 && (data[0].toInt() and 0xFF) == HANDSHAKE_RECORD && (data[1].toInt() and 0xFF) == 0x03

    private class Reader(private val data: ByteArray, val limit: Int) {
        var position = 0
            private set

        fun u8(): Int? {
            if (position + 1 > limit) return null
            return (data[position++].toInt() and 0xFF)
        }

        fun u16(): Int? {
            if (position + 2 > limit) return null
            val value = ((data[position].toInt() and 0xFF) shl 8) or (data[position + 1].toInt() and 0xFF)
            position += 2
            return value
        }

        fun skip(count: Int): Boolean {
            if (count < 0 || position + count > limit) return false
            position += count
            return true
        }

        fun bytes(count: Int): ByteArray? {
            if (count < 0 || position + count > limit) return null
            return data.copyOfRange(position, position + count).also { position += count }
        }
    }
}
