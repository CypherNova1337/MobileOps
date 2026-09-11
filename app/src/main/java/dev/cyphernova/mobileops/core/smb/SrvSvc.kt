package dev.cyphernova.mobileops.core.smb

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Enough DCERPC and NDR to ask a file server what it is sharing.
 *
 * "Null session accepted" on its own is a statement about what might be reachable. What makes it
 * a finding is the answer to the next question — what can a caller with no credentials actually
 * see — and that answer comes from one RPC call over the `srvsvc` pipe.
 *
 * Only the encoding needed for that one call is here. NDR is a large specification and almost
 * none of it applies to a single array of three-field structures.
 */
object SrvSvc {

    /** `srvsvc`, the interface that lists shares. */
    private val SRVSVC_UUID = byteArrayOf(
        0xC8.toByte(), 0x4F, 0x32, 0x4B, 0x70, 0x16, 0xD3.toByte(), 0x01,
        0x12, 0x78, 0x5A, 0x47, 0xBF.toByte(), 0x6E, 0xE1.toByte(), 0x88.toByte(),
    )

    /** NDR itself, as a transfer syntax. */
    private val NDR_UUID = byteArrayOf(
        0x04, 0x5D, 0x88.toByte(), 0x8A.toByte(), 0xEB.toByte(), 0x1C, 0xC9.toByte(), 0x11,
        0x9F.toByte(), 0xE8.toByte(), 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
    )

    private const val PDU_REQUEST = 0
    private const val PDU_RESPONSE = 2
    private const val PDU_BIND = 11
    private const val PDU_BIND_ACK = 12

    private const val OPNUM_NET_SHARE_ENUM = 15

    /** The DCERPC bind that has to succeed before any call is possible. */
    fun bindRequest(callId: Int = 1): ByteArray {
        val body = ByteBuffer.allocate(72).order(ByteOrder.LITTLE_ENDIAN)
        body.putShort(4280)          // max transmit fragment
        body.putShort(4280)          // max receive fragment
        body.putInt(0)               // association group
        body.put(1)                  // one context item
        body.put(0); body.putShort(0)
        body.putShort(0)             // context id
        body.put(1)                  // one transfer syntax
        body.put(0)
        body.put(SRVSVC_UUID); body.putShort(3); body.putShort(0)  // srvsvc v3.0
        body.put(NDR_UUID); body.putShort(2); body.putShort(0)     // NDR v2.0
        return header(PDU_BIND, callId, body.array()) + body.array()
    }

    fun isBindAccepted(response: ByteArray): Boolean =
        response.size > 2 && response[2].toInt() == PDU_BIND_ACK

    /**
     * `NetrShareEnum` at level 1: share name, type and comment for every share.
     *
     * The container is sent empty and the maximum length unbounded, which is how the call asks
     * the server to fill it in.
     */
    fun netShareEnumRequest(serverName: String, callId: Int = 2): ByteArray {
        val stub = ByteBuffer.allocate(1024).order(ByteOrder.LITTLE_ENDIAN)
        putReferentString(stub, "\\\\$serverName")
        stub.putInt(1)              // Level 1
        stub.putInt(1)              // union tag: level 1
        stub.putInt(REFERENT)       // pointer to the container
        stub.putInt(0)              // EntriesRead: nothing yet
        stub.putInt(0)              // Buffer: null, the server allocates
        stub.putInt(-1)             // PreferredMaximumLength: 0xFFFFFFFF, no cap
        stub.putInt(REFERENT)       // pointer to the resume handle
        stub.putInt(0)              // resume from the start

        val body = ByteArray(stub.position())
        stub.flip(); stub.get(body)

        val prefix = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
        prefix.putInt(body.size)    // allocation hint
        prefix.putShort(0)          // presentation context
        prefix.putShort(OPNUM_NET_SHARE_ENUM.toShort())

        val payload = prefix.array() + body
        return header(PDU_REQUEST, callId, payload) + payload
    }

    /** One share, as the server describes it. */
    data class Share(val name: String, val type: Int, val remark: String) {

        /** Administrative shares end in `$` and the type carries a flag saying so. */
        val isAdministrative: Boolean get() = type and TYPE_SPECIAL != 0 || name.endsWith("$")

        val kind: String
            get() = when (type and 0x0F) {
                0 -> "disk"
                1 -> "print queue"
                2 -> "device"
                3 -> "IPC"
                else -> "type 0x%02x".format(type and 0x0F)
            }

        /**
         * Whether this is a share whose contents are the point. IPC and print queues are
         * plumbing; a disk share offered to an anonymous caller is the finding.
         */
        val holdsFiles: Boolean get() = (type and 0x0F) == 0
    }

    /**
     * Reads the share array out of a `NetrShareEnum` response.
     *
     * NDR puts the fixed part of every array element first and the variable-length strings
     * afterwards, in the order the pointers appeared — so the names are not beside the entries
     * they belong to, and the two passes here are not an accident of style.
     */
    fun parseShares(response: ByteArray): List<Share> {
        val stub = responseStub(response) ?: return emptyList()
        val view = ByteBuffer.wrap(stub).order(ByteOrder.LITTLE_ENDIAN)
        var cursor = 0

        fun int(): Int? {
            if (cursor + 4 > stub.size) return null
            val value = view.getInt(cursor)
            cursor += 4
            return value
        }

        if (int() != 1) return emptyList()          // Level
        if (int() != 1) return emptyList()          // union tag
        if (int() == 0) return emptyList()          // container pointer; null means nothing to read
        val entriesRead = int() ?: return emptyList()
        if (entriesRead <= 0 || entriesRead > MAX_SHARES) return emptyList()
        if (int() == 0) return emptyList()          // array pointer
        val maxCount = int() ?: return emptyList()
        if (maxCount < entriesRead) return emptyList()

        // Pass one: the fixed part of each element, which is two pointers and a type.
        val fixed = (0 until entriesRead).map {
            val namePointer = int() ?: return emptyList()
            val type = int() ?: return emptyList()
            val remarkPointer = int() ?: return emptyList()
            Triple(namePointer, type, remarkPointer)
        }

        // Pass two: the strings, in the order their pointers were written.
        fun next(pointer: Int): String {
            if (pointer == 0) return ""
            val (text, after) = readString(stub, view, cursor) ?: return ""
            cursor = after
            return text
        }

        return fixed.mapNotNull { (namePointer, type, remarkPointer) ->
            val name = next(namePointer)
            val remark = next(remarkPointer)
            if (name.isBlank()) null else Share(name, type, remark)
        }
    }

    /**
     * A conformant varying string: a maximum, an offset, an actual length, then that many
     * UTF-16 characters, padded out to a four-byte boundary.
     */
    private fun readString(stub: ByteArray, view: ByteBuffer, start: Int): Pair<String, Int>? {
        if (start + 12 > stub.size) return null
        val actual = view.getInt(start + 8)
        if (actual < 0 || actual > MAX_STRING_CHARS) return null
        val from = start + 12
        val bytes = actual * 2
        if (from + bytes > stub.size) return null
        // NDR counts the terminator in the length, so it arrives as part of the string.
        val text = String(stub, from, bytes, Charsets.UTF_16LE)
            .trimEnd('\u0000', ' ')
        val end = from + bytes
        return text to end + ((4 - (end % 4)) % 4)
    }

    /** The stub data of a DCERPC response, past the common and response headers. */
    fun responseStub(response: ByteArray): ByteArray? {
        if (response.size < RESPONSE_HEADER_BYTES) return null
        if (response[2].toInt() != PDU_RESPONSE) return null
        return response.copyOfRange(RESPONSE_HEADER_BYTES, response.size)
    }

    private fun header(type: Int, callId: Int, body: ByteArray): ByteArray {
        val head = ByteBuffer.allocate(COMMON_HEADER_BYTES).order(ByteOrder.LITTLE_ENDIAN)
        head.put(5)                    // version 5
        head.put(0)                    // version minor 0
        head.put(type.toByte())
        head.put(0x03)                 // first and last fragment
        head.put(byteArrayOf(0x10, 0, 0, 0))  // little-endian, ASCII, IEEE
        head.putShort((COMMON_HEADER_BYTES + body.size).toShort())
        head.putShort(0)               // no authentication
        head.putInt(callId)
        return head.array()
    }

    /** A unique pointer: a non-zero referent id, then the string it points at. */
    private fun putReferentString(out: ByteBuffer, value: String) {
        out.putInt(REFERENT)
        val chars = value.toCharArray()
        val count = chars.size + 1     // NDR counts the terminator
        out.putInt(count)              // MaxCount
        out.putInt(0)                  // Offset
        out.putInt(count)              // ActualCount
        chars.forEach { out.putShort(it.code.toShort()) }
        out.putShort(0)
        // Every NDR construct starts on a four-byte boundary.
        repeat((4 - ((count * 2) % 4)) % 4) { out.put(0) }
    }

    private const val COMMON_HEADER_BYTES = 16

    /** The common header plus alloc hint, context id, cancel count and a reserved byte. */
    private const val RESPONSE_HEADER_BYTES = 24

    /** Any non-zero value identifies a pointer; the value itself carries no meaning. */
    private const val REFERENT = 0x00020000

    private const val TYPE_SPECIAL = 0x80000000.toInt()

    /** Bounds on a hostile reply, so a corrupt length cannot become an allocation. */
    private const val MAX_SHARES = 4096
    private const val MAX_STRING_CHARS = 4096
}
