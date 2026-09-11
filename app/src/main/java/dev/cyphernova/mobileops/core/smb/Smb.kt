package dev.cyphernova.mobileops.core.smb

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Just enough SMB to answer the questions a report should not be asking the operator to go and
 * answer by hand: is SMB1 still enabled, is signing actually required, and will the server talk to
 * someone who presents no credentials at all.
 *
 * All three are reachable before authentication. The negotiate exchange states the signing policy
 * outright, and the NTLM challenge that comes back from an unauthenticated session setup carries
 * the machine's name, its domain, and its OS build — handed to anyone who can open port 445.
 *
 * Everything here is bytes in and bytes out so it can be tested against real captures without a
 * network. The socket work lives in the module.
 */
object Smb {

    // ---- NetBIOS session service -------------------------------------------------------------

    /** SMB over 139 and 445 alike is framed by a four-byte NetBIOS session header. */
    fun frame(payload: ByteArray): ByteArray {
        val out = ByteArray(4 + payload.size)
        out[0] = 0
        out[1] = ((payload.size shr 16) and 0xFF).toByte()
        out[2] = ((payload.size shr 8) and 0xFF).toByte()
        out[3] = (payload.size and 0xFF).toByte()
        payload.copyInto(out, 4)
        return out
    }

    /** The payload length a NetBIOS header declares, or null if the header is not one. */
    fun framedLength(header: ByteArray): Int? {
        if (header.size < 4) return null
        // 0x00 is a session message; 0x85 is a keepalive and carries nothing.
        if (header[0].toInt() != 0x00) return null
        return ((header[1].toInt() and 0xFF) shl 16) or
            ((header[2].toInt() and 0xFF) shl 8) or
            (header[3].toInt() and 0xFF)
    }

    // ---- Dialect probing ---------------------------------------------------------------------

    /**
     * An SMB1 negotiate offering only the NT LM 0.12 dialect.
     *
     * This is the definitive test for SMB1. A server with SMB1 disabled either refuses the
     * connection or answers in SMB2; one that answers in SMB1 with a chosen dialect is still
     * running the protocol behind WannaCry and NotPetya.
     */
    fun smb1NegotiateRequest(): ByteArray {
        val dialects = "NT LM 0.12".toByteArray(Charsets.US_ASCII)
        val body = ByteBuffer.allocate(3 + 1 + dialects.size + 1).order(ByteOrder.LITTLE_ENDIAN)
        body.put(0)                                   // WordCount
        body.putShort((dialects.size + 2).toShort())  // ByteCount
        body.put(0x02)                                // dialect buffer format
        body.put(dialects)
        body.put(0)                                   // terminator

        val header = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN)
        header.put(byteArrayOf(0xFF.toByte(), 'S'.code.toByte(), 'M'.code.toByte(), 'B'.code.toByte()))
        header.put(SMB1_COM_NEGOTIATE)
        header.putInt(0)                              // NTSTATUS
        header.put(0x18)                              // Flags: canonical paths, case insensitive
        header.putShort(0xC853.toShort())             // Flags2: unicode, NT status, extended security
        header.putShort(0)                            // PIDHigh
        header.put(ByteArray(8))                      // signature
        header.putShort(0)                            // reserved
        header.putShort(0)                            // TID
        header.putShort(0xFEFF.toShort())             // PIDLow
        header.putShort(0)                            // UID
        header.putShort(0)                            // MID

        return frame(header.array() + body.array())
    }

    /** Which protocol family a response header belongs to, if either. */
    fun dialectFamilyOf(response: ByteArray): Family? {
        val body = stripFrame(response) ?: return null
        if (body.size < 4) return null
        val magic = body.copyOfRange(1, 4)
        if (!magic.contentEquals(SMB_LETTERS)) return null
        return when (body[0].toInt() and 0xFF) {
            0xFF -> Family.SMB1
            0xFE -> Family.SMB2
            else -> null
        }
    }

    enum class Family { SMB1, SMB2 }

    // ---- SMB2 --------------------------------------------------------------------------------

    /**
     * An SMB2 negotiate offering every dialect from 2.0.2 to 3.1.1.
     *
     * 3.1.1 requires a preauth-integrity negotiate context or the server is entitled to reject the
     * request outright, so one is supplied. Without it a server configured to require 3.1.1 — which
     * is the hardened configuration worth recognising — would look like a server that does not
     * speak SMB2 at all.
     */
    fun smb2NegotiateRequest(clientGuid: ByteArray = ByteArray(16), salt: ByteArray = ByteArray(32)): ByteArray {
        require(clientGuid.size == 16) { "client GUID is 16 bytes" }
        require(salt.size == 32) { "preauth salt is 32 bytes" }

        val dialects = listOf(0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
        val bodyFixed = 36
        val dialectBytes = dialects.size * 2
        // Negotiate contexts must start on an 8-byte boundary measured from the header.
        val unaligned = SMB2_HEADER_BYTES + bodyFixed + dialectBytes
        val padding = (8 - (unaligned % 8)) % 8
        val contextOffset = unaligned + padding

        val preauth = ByteBuffer.allocate(38).order(ByteOrder.LITTLE_ENDIAN)
        preauth.putShort(1)              // one hash algorithm
        preauth.putShort(32)             // salt length
        preauth.putShort(0x0001)         // SHA-512
        preauth.put(salt)

        val body = ByteBuffer.allocate(bodyFixed + dialectBytes + padding + 8 + preauth.capacity())
            .order(ByteOrder.LITTLE_ENDIAN)
        body.putShort(36)                                   // StructureSize
        body.putShort(dialects.size.toShort())
        body.putShort(SIGNING_ENABLED.toShort())
        body.putShort(0)                                    // Reserved
        body.putInt(0)                                      // Capabilities
        body.put(clientGuid)
        body.putInt(contextOffset)                          // NegotiateContextOffset
        body.putShort(1)                                    // NegotiateContextCount
        body.putShort(0)                                    // Reserved2
        dialects.forEach { body.putShort(it.toShort()) }
        body.put(ByteArray(padding))
        body.putShort(0x0001)                               // PREAUTH_INTEGRITY_CAPABILITIES
        body.putShort(preauth.capacity().toShort())
        body.putInt(0)                                      // Reserved
        body.put(preauth.array())

        return frame(smb2Header(SMB2_NEGOTIATE, messageId = 0) + body.array())
    }

    /**
     * A session setup carrying an NTLM negotiate, sent with no credentials.
     *
     * The point is the reply. A server that is willing to start NTLM tells an anonymous caller its
     * NetBIOS name, its domain, its DNS names and its OS build in the challenge.
     */
    fun smb2SessionSetupRequest(securityBlob: ByteArray, messageId: Long, sessionId: Long = 0): ByteArray {
        val bodyFixed = 24
        val body = ByteBuffer.allocate(bodyFixed + securityBlob.size).order(ByteOrder.LITTLE_ENDIAN)
        body.putShort(25)                                            // StructureSize
        body.put(0)                                                  // Flags
        body.put(SIGNING_ENABLED.toByte())                           // SecurityMode
        body.putInt(0)                                               // Capabilities
        body.putInt(0)                                               // Channel
        body.putShort((SMB2_HEADER_BYTES + bodyFixed).toShort())     // SecurityBufferOffset
        body.putShort(securityBlob.size.toShort())
        body.putLong(0)                                              // PreviousSessionId
        body.put(securityBlob)

        return frame(smb2Header(SMB2_SESSION_SETUP, messageId, sessionId) + body.array())
    }

    private fun smb2Header(
        command: Int,
        messageId: Long,
        sessionId: Long = 0,
        treeId: Int = 0,
    ): ByteArray {
        val header = ByteBuffer.allocate(SMB2_HEADER_BYTES).order(ByteOrder.LITTLE_ENDIAN)
        header.put(0xFE.toByte())
        header.put(SMB_LETTERS)
        header.putShort(SMB2_HEADER_BYTES.toShort())  // StructureSize
        header.putShort(0)                            // CreditCharge
        header.putInt(0)                              // Status / ChannelSequence
        header.putShort(command.toShort())
        header.putShort(31)                           // credits requested
        header.putInt(0)                              // Flags
        header.putInt(0)                              // NextCommand
        header.putLong(messageId)
        header.putInt(0)                              // Reserved
        header.putInt(treeId)
        header.putLong(sessionId)
        header.put(ByteArray(16))                     // Signature
        return header.array()
    }

    /** What an SMB2 negotiate response says about the server. */
    data class Negotiated(
        val dialect: Int,
        val signingEnabled: Boolean,
        val signingRequired: Boolean,
        val serverGuid: ByteArray,
        val securityBlob: ByteArray,
    ) {
        /** The dialect as it is written in documentation and in a report: 0x0311 is "3.1.1". */
        val dialectName: String
            get() = when (dialect) {
                0x0202 -> "2.0.2"
                0x0210 -> "2.1"
                0x0300 -> "3.0"
                0x0302 -> "3.0.2"
                0x0311 -> "3.1.1"
                0x02FF -> "2.wildcard"
                else -> "0x%04x".format(dialect)
            }

        override fun equals(other: Any?): Boolean = this === other
        override fun hashCode(): Int = dialect
    }

    fun parseNegotiateResponse(response: ByteArray): Negotiated? {
        val body = stripFrame(response) ?: return null
        if (body.size < SMB2_HEADER_BYTES + 64) return null
        if ((body[0].toInt() and 0xFF) != 0xFE) return null

        val view = ByteBuffer.wrap(body).order(ByteOrder.LITTLE_ENDIAN)
        val structureSize = view.getShort(SMB2_HEADER_BYTES).toInt() and 0xFFFF
        if (structureSize != 65) return null

        val securityMode = view.getShort(SMB2_HEADER_BYTES + 2).toInt() and 0xFFFF
        val dialect = view.getShort(SMB2_HEADER_BYTES + 4).toInt() and 0xFFFF
        val guid = body.copyOfRange(SMB2_HEADER_BYTES + 8, SMB2_HEADER_BYTES + 24)

        // The security buffer offset is measured from the start of the SMB2 header, not the body.
        val blobOffset = view.getShort(SMB2_HEADER_BYTES + 56).toInt() and 0xFFFF
        val blobLength = view.getShort(SMB2_HEADER_BYTES + 58).toInt() and 0xFFFF
        val blob = if (blobOffset in 0..body.size && blobOffset + blobLength <= body.size) {
            body.copyOfRange(blobOffset, blobOffset + blobLength)
        } else {
            ByteArray(0)
        }

        return Negotiated(
            dialect = dialect,
            signingEnabled = securityMode and SIGNING_ENABLED != 0,
            signingRequired = securityMode and SIGNING_REQUIRED != 0,
            serverGuid = guid,
            securityBlob = blob,
        )
    }

    /** The NTSTATUS an SMB2 response carries. 0 is success; everything else is a refusal. */
    fun statusOf(response: ByteArray): Int? {
        val body = stripFrame(response) ?: return null
        if (body.size < SMB2_HEADER_BYTES || (body[0].toInt() and 0xFF) != 0xFE) return null
        return ByteBuffer.wrap(body).order(ByteOrder.LITTLE_ENDIAN).getInt(8)
    }

    /** Whether a successful session setup was granted as the null user rather than a real one. */
    fun isNullSession(response: ByteArray): Boolean {
        val body = stripFrame(response) ?: return false
        if (body.size < SMB2_HEADER_BYTES + 4) return false
        val flags = ByteBuffer.wrap(body).order(ByteOrder.LITTLE_ENDIAN)
            .getShort(SMB2_HEADER_BYTES + 2).toInt() and 0xFFFF
        return flags and SESSION_FLAG_IS_NULL != 0
    }

    /** Drops the NetBIOS framing, checking the declared length covers what arrived. */
    fun stripFrame(response: ByteArray): ByteArray? {
        val declared = framedLength(response) ?: return null
        if (declared <= 0 || response.size < 4 + declared) return null
        return response.copyOfRange(4, 4 + declared)
    }


    // ---- Reaching a share ----------------------------------------------------------------------

    /**
     * A tree connect to `\\host\share`.
     *
     * The response status alone separates three cases an operator needs kept apart: the share
     * exists and this session can reach it, the share exists and the session is refused, or there
     * is no such share. Reporting "null session accepted" without any of that says nothing about
     * what a stranger can actually read.
     */
    fun smb2TreeConnectRequest(host: String, share: String, messageId: Long, sessionId: Long): ByteArray {
        val path = "\\\\$host\\$share".toByteArray(Charsets.UTF_16LE)
        val bodyFixed = 8
        val body = ByteBuffer.allocate(bodyFixed + path.size).order(ByteOrder.LITTLE_ENDIAN)
        body.putShort(9)                                          // StructureSize
        body.putShort(0)                                          // Flags / Reserved
        body.putShort((SMB2_HEADER_BYTES + bodyFixed).toShort())  // PathOffset
        body.putShort(path.size.toShort())
        body.put(path)
        return frame(smb2Header(SMB2_TREE_CONNECT, messageId, sessionId) + body.array())
    }

    /** The tree id a successful tree connect granted, read from the response header. */
    fun treeIdOf(response: ByteArray): Int {
        val body = stripFrame(response) ?: return 0
        if (body.size < SMB2_HEADER_BYTES) return 0
        return ByteBuffer.wrap(body).order(ByteOrder.LITTLE_ENDIAN).getInt(36)
    }

    /** Opens a named pipe — `srvsvc` is the one that can list shares. */
    fun smb2CreateRequest(
        name: String,
        messageId: Long,
        sessionId: Long,
        treeId: Int,
    ): ByteArray {
        val encoded = name.toByteArray(Charsets.UTF_16LE)
        val bodyFixed = 56
        val body = ByteBuffer.allocate(bodyFixed + encoded.size).order(ByteOrder.LITTLE_ENDIAN)
        body.putShort(57)                                         // StructureSize
        body.put(0)                                               // SecurityFlags
        body.put(0)                                               // RequestedOplockLevel
        body.putInt(2)                                            // Impersonation
        body.putLong(0)                                           // SmbCreateFlags
        body.putLong(0)                                           // Reserved
        body.putInt(0x0012019F)                                   // DesiredAccess: read/write pipe
        body.putInt(0)                                            // FileAttributes
        body.putInt(7)                                            // ShareAccess: read/write/delete
        body.putInt(1)                                            // CreateDisposition: FILE_OPEN
        body.putInt(0x40)                                         // CreateOptions: non-directory
        body.putShort((SMB2_HEADER_BYTES + bodyFixed).toShort())  // NameOffset
        body.putShort(encoded.size.toShort())
        body.putInt(0)                                            // CreateContextsOffset
        body.putInt(0)                                            // CreateContextsLength
        body.put(encoded)
        return frame(smb2Header(SMB2_CREATE, messageId, sessionId, treeId) + body.array())
    }

    /** The 16-byte handle a create returned, or null if it did not succeed. */
    fun fileIdOf(response: ByteArray): ByteArray? {
        val body = stripFrame(response) ?: return null
        if (body.size < SMB2_HEADER_BYTES + 80) return null
        if (statusOf(response) != STATUS_SUCCESS) return null
        return body.copyOfRange(SMB2_HEADER_BYTES + 64, SMB2_HEADER_BYTES + 80)
    }

    /**
     * Writes to a named pipe and reads the reply in one exchange.
     *
     * A DCERPC call is a write followed by a read, and doing it as two SMB operations means two
     * round trips and a handle that can go stale between them. FSCTL_PIPE_TRANSCEIVE is the one
     * operation that does both.
     */
    fun smb2PipeTransceiveRequest(
        fileId: ByteArray,
        input: ByteArray,
        messageId: Long,
        sessionId: Long,
        treeId: Int,
    ): ByteArray {
        require(fileId.size == 16) { "a file id is 16 bytes" }
        val bodyFixed = 56
        val inputOffset = SMB2_HEADER_BYTES + bodyFixed
        val body = ByteBuffer.allocate(bodyFixed + input.size).order(ByteOrder.LITTLE_ENDIAN)
        body.putShort(57)                       // StructureSize
        body.putShort(0)                        // Reserved
        body.putInt(FSCTL_PIPE_TRANSCEIVE)
        body.put(fileId)
        body.putInt(inputOffset)
        body.putInt(input.size)
        body.putInt(0)                          // MaxInputResponse
        body.putInt(inputOffset + input.size)   // OutputOffset
        body.putInt(0)                          // OutputCount
        body.putInt(MAX_PIPE_RESPONSE)
        body.putInt(1)                          // IS_FSCTL
        body.putInt(0)                          // Reserved2
        body.put(input)
        return frame(smb2Header(SMB2_IOCTL, messageId, sessionId, treeId) + body.array())
    }

    /** The pipe's reply, sliced out of an ioctl response. */
    fun ioctlOutput(response: ByteArray): ByteArray? {
        val body = stripFrame(response) ?: return null
        if (body.size < SMB2_HEADER_BYTES + 48) return null
        val view = ByteBuffer.wrap(body).order(ByteOrder.LITTLE_ENDIAN)
        // Measured from the start of the header, like every other offset in SMB2.
        val offset = view.getInt(SMB2_HEADER_BYTES + 32)
        val count = view.getInt(SMB2_HEADER_BYTES + 36)
        if (offset < 0 || count <= 0 || offset.toLong() + count > body.size) return null
        return body.copyOfRange(offset, offset + count)
    }

    const val SMB2_HEADER_BYTES = 64
    const val SMB2_NEGOTIATE = 0x0000
    const val SMB2_SESSION_SETUP = 0x0001
    const val SMB2_TREE_CONNECT = 0x0003
    const val SMB2_CREATE = 0x0005
    const val SMB2_IOCTL = 0x000B

    const val FSCTL_PIPE_TRANSCEIVE = 0x0011C017

    const val STATUS_BAD_NETWORK_NAME = 0xC00000CC.toInt()
    const val STATUS_NOT_FOUND = 0xC0000225.toInt()

    /** A share list is a few kilobytes; a reply far past that is not one. */
    private const val MAX_PIPE_RESPONSE = 64 * 1024

    const val STATUS_SUCCESS = 0

    /**
     * Not a failure: the server is saying it will answer on this connection shortly. A caller
     * that treats the interim reply as the answer reads a result that was on its way as empty.
     */
    const val STATUS_PENDING = 0x00000103
    const val STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016.toInt()
    const val STATUS_LOGON_FAILURE = 0xC000006D.toInt()
    const val STATUS_ACCESS_DENIED = 0xC0000022.toInt()

    private const val SIGNING_ENABLED = 0x0001
    private const val SIGNING_REQUIRED = 0x0002
    private const val SESSION_FLAG_IS_NULL = 0x0002
    private const val SMB1_COM_NEGOTIATE: Byte = 0x72

    private val SMB_LETTERS = byteArrayOf('S'.code.toByte(), 'M'.code.toByte(), 'B'.code.toByte())
}
