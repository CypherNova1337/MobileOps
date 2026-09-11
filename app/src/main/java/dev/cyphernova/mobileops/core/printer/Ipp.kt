package dev.cyphernova.mobileops.core.printer

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * The one IPP operation worth sending unauthenticated: `Get-Printer-Attributes`.
 *
 * IPP is the modern printing protocol and it answers this query to anyone, by design — a client
 * has to be able to discover a printer's capabilities before it can submit a job. What comes back
 * is the make and model, the firmware, the queue length, and on a great many devices the location
 * string and the administrator's contact details, which an assessor gets for one request against
 * a port that is open on almost every office network.
 *
 * Nothing here submits, cancels or alters a job. The encoding is big-endian throughout, unlike
 * every other protocol in this codebase.
 */
object Ipp {

    private const val VERSION_1_1 = 0x0101
    private const val OP_GET_PRINTER_ATTRIBUTES = 0x000B

    private const val TAG_OPERATION_ATTRIBUTES = 0x01
    private const val TAG_END_OF_ATTRIBUTES = 0x03
    private const val TAG_INTEGER = 0x21
    private const val TAG_BOOLEAN = 0x22
    private const val TAG_ENUM = 0x23
    private const val TAG_URI = 0x45
    private const val TAG_CHARSET = 0x47
    private const val TAG_NATURAL_LANGUAGE = 0x48

    /** A `Get-Printer-Attributes` request for [printerUri]. */
    fun getPrinterAttributesRequest(printerUri: String, requestId: Int = 1): ByteArray {
        val out = ByteBuffer.allocate(1024).order(ByteOrder.BIG_ENDIAN)
        out.putShort(VERSION_1_1.toShort())
        out.putShort(OP_GET_PRINTER_ATTRIBUTES.toShort())
        out.putInt(requestId)

        out.put(TAG_OPERATION_ATTRIBUTES.toByte())
        // The order is fixed by the specification: charset, then language, then the printer URI.
        putAttribute(out, TAG_CHARSET, "attributes-charset", "utf-8")
        putAttribute(out, TAG_NATURAL_LANGUAGE, "attributes-natural-language", "en-us")
        putAttribute(out, TAG_URI, "printer-uri", printerUri)
        out.put(TAG_END_OF_ATTRIBUTES.toByte())

        val body = ByteArray(out.position())
        out.flip()
        out.get(body)
        return body
    }

    private fun putAttribute(out: ByteBuffer, tag: Int, name: String, value: String) {
        val nameBytes = name.toByteArray(Charsets.US_ASCII)
        val valueBytes = value.toByteArray(Charsets.UTF_8)
        out.put(tag.toByte())
        out.putShort(nameBytes.size.toShort())
        out.put(nameBytes)
        out.putShort(valueBytes.size.toShort())
        out.put(valueBytes)
    }

    /** What the printer said about itself. */
    data class Attributes(val statusCode: Int, val values: Map<String, List<String>>) {

        val isSuccess: Boolean get() = statusCode in 0x0000..0x00FF

        fun first(name: String): String? = values[name]?.firstOrNull()?.takeIf { it.isNotBlank() }

        val makeAndModel: String? get() = first("printer-make-and-model")
        val location: String? get() = first("printer-location")
        val info: String? get() = first("printer-info")
        val firmware: String?
            get() = first("printer-firmware-string-version")
                ?: first("printer-firmware-version")
        val queuedJobs: Int? get() = first("queued-job-count")?.toIntOrNull()

        /**
         * Whether the printer says it will accept a job from an unauthenticated client.
         *
         * `none` in `uri-authentication-supported` is the device stating outright that it wants no
         * credential, which is worth more than inferring it from a request that happened to work.
         */
        val acceptsUnauthenticated: Boolean
            get() = values["uri-authentication-supported"].orEmpty()
                .any { it.equals("none", ignoreCase = true) }

        /** Whether any of its advertised URIs are unencrypted. */
        val hasCleartextUri: Boolean
            get() = values["printer-uri-supported"].orEmpty()
                .any { it.startsWith("ipp://", ignoreCase = true) }
    }

    /**
     * Reads an IPP response.
     *
     * Attributes arrive as a flat stream of tag/name/value triples where a zero-length name means
     * "another value for the attribute before me", so a multi-valued attribute is not marked as
     * one — it is inferred from the gap, which is why the last name is carried forward.
     */
    fun parse(response: ByteArray): Attributes? {
        if (response.size < 8) return null
        val view = ByteBuffer.wrap(response).order(ByteOrder.BIG_ENDIAN)
        val statusCode = view.getShort(2).toInt() and 0xFFFF

        val values = mutableMapOf<String, MutableList<String>>()
        var cursor = 8
        var lastName: String? = null

        while (cursor < response.size) {
            val tag = response[cursor].toInt() and 0xFF
            cursor++
            if (tag == TAG_END_OF_ATTRIBUTES) break
            // Tags below 0x10 delimit a group rather than carrying a value.
            if (tag < 0x10) {
                lastName = null
                continue
            }

            if (cursor + 2 > response.size) break
            val nameLength = view.getShort(cursor).toInt() and 0xFFFF
            cursor += 2
            if (cursor + nameLength > response.size) break
            val name = if (nameLength > 0) {
                String(response, cursor, nameLength, Charsets.UTF_8).also { lastName = it }
            } else {
                lastName ?: return null
            }
            cursor += nameLength

            if (cursor + 2 > response.size) break
            val valueLength = view.getShort(cursor).toInt() and 0xFFFF
            cursor += 2
            if (cursor + valueLength > response.size) break
            val value = decodeValue(tag, response, cursor, valueLength)
            cursor += valueLength

            values.getOrPut(name) { mutableListOf() }.add(value)
        }

        return Attributes(statusCode, values)
    }

    /** Integers and booleans are binary; everything else this cares about is text. */
    private fun decodeValue(tag: Int, data: ByteArray, offset: Int, length: Int): String = when {
        (tag == TAG_INTEGER || tag == TAG_ENUM) && length == 4 ->
            ByteBuffer.wrap(data, offset, 4).order(ByteOrder.BIG_ENDIAN).int.toString()
        tag == TAG_BOOLEAN && length == 1 -> (data[offset].toInt() != 0).toString()
        else -> String(data, offset, length, Charsets.UTF_8)
    }
}
