package dev.cyphernova.mobileops.core.smb

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * The NTLM messages needed to start — and deliberately not finish — an authentication.
 *
 * NTLM's second message is sent before the client has proved anything. It carries the server's
 * NetBIOS name, its domain, its DNS names and, where the server advertises a version, its OS
 * build. That is an unauthenticated disclosure to anyone who can reach port 445, and on an estate
 * it is usually the first thing that turns a list of addresses into a map of the domain.
 *
 * Nothing here computes a credential response. The third message is sent as the null user, which
 * asks the server one question — will you talk to nobody? — without presenting or guessing any
 * password, so it cannot lock an account out. There is no account.
 */
object Ntlm {

    /** `NTLMSSP` followed by a NUL. Written as bytes because the terminator is part of it. */
    private val SIGNATURE = byteArrayOf(
        'N'.code.toByte(), 'T'.code.toByte(), 'L'.code.toByte(), 'M'.code.toByte(),
        'S'.code.toByte(), 'S'.code.toByte(), 'P'.code.toByte(), 0,
    )

    private const val NEGOTIATE_UNICODE = 0x00000001
    private const val REQUEST_TARGET = 0x00000004
    private const val NEGOTIATE_NTLM = 0x00000200
    private const val NEGOTIATE_ANONYMOUS = 0x00000800
    private const val NEGOTIATE_ALWAYS_SIGN = 0x00008000
    private const val NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
    private const val NEGOTIATE_TARGET_INFO = 0x00800000
    private const val NEGOTIATE_VERSION = 0x02000000
    private const val NEGOTIATE_128 = 0x20000000
    private val NEGOTIATE_56 = 0x80000000.toInt()

    private val CLIENT_FLAGS = NEGOTIATE_UNICODE or REQUEST_TARGET or NEGOTIATE_NTLM or
        NEGOTIATE_ALWAYS_SIGN or NEGOTIATE_EXTENDED_SESSIONSECURITY or NEGOTIATE_TARGET_INFO or
        NEGOTIATE_128 or NEGOTIATE_56

    /** NTLM NEGOTIATE — the opening message, naming no domain and no workstation. */
    fun negotiate(): ByteArray {
        val out = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN)
        out.put(SIGNATURE)
        out.putInt(1)
        out.putInt(CLIENT_FLAGS)
        out.putShort(0); out.putShort(0); out.putInt(32)  // DomainName: absent
        out.putShort(0); out.putShort(0); out.putInt(32)  // Workstation: absent
        return out.array()
    }

    /**
     * NTLM AUTHENTICATE as the null user: no domain, no user, no challenge response.
     *
     * The LM field carries a single zero byte and the NT field is empty, which is what the
     * specification says an anonymous authenticate looks like. A server that answers this with
     * success has null sessions enabled.
     */
    fun authenticateAnonymous(): ByteArray {
        val header = 64
        val out = ByteBuffer.allocate(header + 1).order(ByteOrder.LITTLE_ENDIAN)
        out.put(SIGNATURE)
        out.putInt(3)
        out.putShort(1); out.putShort(1); out.putInt(header)      // LmChallengeResponse
        out.putShort(0); out.putShort(0); out.putInt(header + 1)  // NtChallengeResponse
        out.putShort(0); out.putShort(0); out.putInt(header + 1)  // DomainName
        out.putShort(0); out.putShort(0); out.putInt(header + 1)  // UserName
        out.putShort(0); out.putShort(0); out.putInt(header + 1)  // Workstation
        out.putShort(0); out.putShort(0); out.putInt(header + 1)  // EncryptedRandomSessionKey
        out.putInt(CLIENT_FLAGS or NEGOTIATE_ANONYMOUS)
        out.put(0)
        return out.array()
    }

    /** What a server volunteered in its challenge, before being asked to trust anyone. */
    data class Challenge(
        val targetName: String? = null,
        val netbiosComputer: String? = null,
        val netbiosDomain: String? = null,
        val dnsComputer: String? = null,
        val dnsDomain: String? = null,
        val dnsForest: String? = null,
        val osVersion: String? = null,
    ) {
        /**
         * True when the names describe a domain member rather than a standalone machine. On a
         * workgroup box the DNS computer name and the DNS domain are the same string.
         */
        val isDomainJoined: Boolean
            get() = !dnsDomain.isNullOrBlank() && !dnsComputer.isNullOrBlank() &&
                !dnsComputer.equals(dnsDomain, ignoreCase = true)

        fun describe(): String = buildString {
            netbiosComputer?.let { append("Host '$it'. ") }
            netbiosDomain?.let { append("Domain or workgroup '$it'. ") }
            dnsDomain?.let { append("DNS domain '$it'. ") }
            dnsForest?.takeIf { !it.equals(dnsDomain, ignoreCase = true) }
                ?.let { append("Forest '$it'. ") }
            osVersion?.let { append("OS version $it. ") }
        }.trim()
    }

    /**
     * Finds and parses an NTLM challenge anywhere inside [buffer].
     *
     * Servers return the challenge raw or wrapped in a SPNEGO token depending on what was offered,
     * and the wrapper carries nothing this needs. Locating the signature is both simpler and more
     * robust than decoding ASN.1 to arrive at the same bytes.
     */
    fun parseChallenge(buffer: ByteArray): Challenge? {
        val start = indexOfSignature(buffer) ?: return null
        val message = buffer.copyOfRange(start, buffer.size)
        if (message.size < 48) return null

        val view = ByteBuffer.wrap(message).order(ByteOrder.LITTLE_ENDIAN)
        if (view.getInt(8) != 2) return null

        val targetName = readField(message, view, lengthAt = 12, offsetAt = 16)
        val flags = view.getInt(20)
        val targetInfo = readFieldBytes(message, view, lengthAt = 40, offsetAt = 44)

        // The version block sits between the fixed fields and the payload, and only when the
        // server said it would send one.
        val osVersion = if (flags and NEGOTIATE_VERSION != 0 && message.size >= 56) {
            val major = message[48].toInt() and 0xFF
            val minor = message[49].toInt() and 0xFF
            val build = view.getShort(50).toInt() and 0xFFFF
            "$major.$minor build $build"
        } else {
            null
        }

        val pairs = parseTargetInfo(targetInfo)
        return Challenge(
            targetName = targetName,
            netbiosComputer = pairs[AV_NB_COMPUTER],
            netbiosDomain = pairs[AV_NB_DOMAIN],
            dnsComputer = pairs[AV_DNS_COMPUTER],
            dnsDomain = pairs[AV_DNS_DOMAIN],
            dnsForest = pairs[AV_DNS_FOREST],
            osVersion = osVersion,
        )
    }

    /** The AV_PAIR list the challenge carries, decoded to id and value. */
    private fun parseTargetInfo(info: ByteArray): Map<Int, String> {
        val out = mutableMapOf<Int, String>()
        val view = ByteBuffer.wrap(info).order(ByteOrder.LITTLE_ENDIAN)
        var cursor = 0
        while (cursor + 4 <= info.size) {
            val id = view.getShort(cursor).toInt() and 0xFFFF
            val length = view.getShort(cursor + 2).toInt() and 0xFFFF
            cursor += 4
            if (id == AV_EOL) break
            if (cursor + length > info.size) break
            if (id in TEXT_PAIRS && length > 0) {
                out[id] = String(info, cursor, length, Charsets.UTF_16LE)
            }
            cursor += length
        }
        return out
    }

    private fun readField(message: ByteArray, view: ByteBuffer, lengthAt: Int, offsetAt: Int): String? {
        val bytes = readFieldBytes(message, view, lengthAt, offsetAt)
        return if (bytes.isEmpty()) null else String(bytes, Charsets.UTF_16LE)
    }

    private fun readFieldBytes(message: ByteArray, view: ByteBuffer, lengthAt: Int, offsetAt: Int): ByteArray {
        if (message.size < offsetAt + 4) return ByteArray(0)
        val length = view.getShort(lengthAt).toInt() and 0xFFFF
        val offset = view.getInt(offsetAt)
        if (length <= 0 || offset < 0 || offset.toLong() + length > message.size) return ByteArray(0)
        return message.copyOfRange(offset, offset + length)
    }

    private fun indexOfSignature(buffer: ByteArray): Int? {
        outer@ for (start in 0..buffer.size - SIGNATURE.size) {
            for (index in SIGNATURE.indices) {
                if (buffer[start + index] != SIGNATURE[index]) continue@outer
            }
            return start
        }
        return null
    }

    private const val AV_EOL = 0x0000
    private const val AV_NB_COMPUTER = 0x0001
    private const val AV_NB_DOMAIN = 0x0002
    private const val AV_DNS_COMPUTER = 0x0003
    private const val AV_DNS_DOMAIN = 0x0004
    private const val AV_DNS_FOREST = 0x0005

    private val TEXT_PAIRS = setOf(
        AV_NB_COMPUTER, AV_NB_DOMAIN, AV_DNS_COMPUTER, AV_DNS_DOMAIN, AV_DNS_FOREST,
    )
}
