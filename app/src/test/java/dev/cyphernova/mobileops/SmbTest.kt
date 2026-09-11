package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.smb.Ntlm
import dev.cyphernova.mobileops.core.smb.Smb
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Wire-format tests against responses shaped exactly as a server sends them.
 *
 * Every offset in SMB is measured from the start of the SMB2 header rather than the start of the
 * body it appears in, and getting that wrong does not throw — it silently reads the wrong field
 * and reports a signing policy or an OS version that was never on the wire. So the vectors here
 * are whole framed messages, built field by field, rather than fragments.
 */
class SmbTest {

    private fun hex(text: String): ByteArray =
        text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    // A Windows Server 2022 domain controller: signing required, 3.1.1.
    private val negotiateSigningRequired = hex(
        "0000008dfe534d4240000000000000000000010001000000000000000000000000000000000000000000" +
        "000000000000000000000000000000000000000000000000000041000300110300000001020304050607" +
        "08090a0b0c0d0e0f2f000000000080000000800000008000000000000000000000000000000000008000" +
        "0d000000000060607600000000000000000000",
    )

    // The same exchange from a host where signing is merely enabled, on dialect 2.1.
    private val negotiateSigningEnabledOnly = hex(
        "0000008dfe534d4240000000000000000000010001000000000000000000000000000000000000000000" +
        "000000000000000000000000000000000000000000000000000041000100100200000001020304050607" +
        "08090a0b0c0d0e0f2f000000000001000000010000000100000000000000000000000000000000008000" +
        "0d000000000060607600000000000000000000",
    )

    private val sessionSetupChallenge = hex(
        "00000114fe534d4240000000160000c00100010001000000000000000000000000000000000000000000" +
        "0000000000000000000000000000000000000000000000000000090000004800cc004e544c4d53535000" +
        "020000000e000e0038000000058288a20123456789abcdef000000000000000086008600460000000a00" +
        "7c4f0000000f56004f004900440053004500430002000e0056004f004900440053004500430001000800" +
        "440043003000310004001a0076006f00690064007300650063002e006c006f00630061006c0003002400" +
        "44004300300031002e0076006f00690064007300650063002e006c006f00630061006c0005001a007600" +
        "6f00690064007300650063002e006c006f00630061006c0000000000",
    )

    private val sessionSetupNullAccepted = hex(
        "00000051fe534d4240000000000000000100010001000000000000000000000000000000000000000000" +
        "00000000000000000000000000000000000000000000000000000900020048000900a1073005a0030a01" +
        "00",
    )

    /**
     * A Netgear router's Samba, from a live run: it names itself DRIVE as both host and domain,
     * pads the DNS name pairs with a single space, and claims 6.1 with no build number.
     */
    private val sambaChallenge = hex(
        "000000b6fe534d4240000000160000c00100010001000000000000000000000000000000000000000000" +
        "00000000000000000000000000000000000000000000000000000900000048006e004e544c4d53535000" +
        "020000000a000a0038000000058288a2112233445566778800000000000000002c002c00420000000601" +
        "00000000000f4400520049005600450002000a004400520049005600450001000a004400520049005600" +
        "450004000200200003000200200000000000",
    )

    private val smb1NegotiateResponse = hex(
        "00000045ff534d4272000000009853c80000000000000000000000000000fffe00000000110000000000" +
        "00000000000000000000000000000000000000000000000000000000000000",
    )

    // ---- Framing -------------------------------------------------------------------------------

    @Test
    fun `the netbios header declares the payload length in big-endian`() {
        val framed = Smb.frame(ByteArray(0x1234))
        assertEquals(0, framed[0].toInt())
        assertEquals(0x1234, Smb.framedLength(framed))
        assertEquals(4 + 0x1234, framed.size)
    }

    @Test
    fun `a keepalive is not treated as a message`() {
        assertNull(Smb.framedLength(byteArrayOf(0x85.toByte(), 0, 0, 0)))
    }

    /** A truncated read must fail rather than hand back a half-parsed message. */
    @Test
    fun `a frame shorter than its declared length is rejected`() {
        val truncated = Smb.frame(ByteArray(100)).copyOfRange(0, 40)
        assertNull(Smb.stripFrame(truncated))
    }

    // ---- Requests ------------------------------------------------------------------------------

    @Test
    fun `the smb2 negotiate is well formed and offers every dialect through 3_1_1`() {
        val request = Smb.smb2NegotiateRequest()
        val body = Smb.stripFrame(request)!!
        val view = ByteBuffer.wrap(body).order(ByteOrder.LITTLE_ENDIAN)

        assertEquals(0xFE, body[0].toInt() and 0xFF)
        assertEquals("SMB", String(body, 1, 3, Charsets.US_ASCII))
        assertEquals(64, view.getShort(4).toInt())
        assertEquals(Smb.SMB2_NEGOTIATE, view.getShort(12).toInt())

        assertEquals(36, view.getShort(64).toInt())
        val dialectCount = view.getShort(66).toInt()
        assertEquals(5, dialectCount)
        val dialects = (0 until dialectCount).map { view.getShort(64 + 36 + it * 2).toInt() and 0xFFFF }
        assertEquals(listOf(0x0202, 0x0210, 0x0300, 0x0302, 0x0311), dialects)
    }

    /**
     * 3.1.1 is only legal with a preauth-integrity context, and the context list has to start on
     * an eight-byte boundary measured from the header. A server is entitled to reject a request
     * that gets this wrong, which would look exactly like a host that does not speak SMB2.
     */
    @Test
    fun `the negotiate context is present and eight-byte aligned`() {
        val body = Smb.stripFrame(Smb.smb2NegotiateRequest())!!
        val view = ByteBuffer.wrap(body).order(ByteOrder.LITTLE_ENDIAN)

        val contextOffset = view.getInt(64 + 28)
        val contextCount = view.getShort(64 + 32).toInt()
        assertEquals(1, contextCount)
        assertEquals("context offset must be 8-byte aligned", 0, contextOffset % 8)
        assertTrue(contextOffset + 8 <= body.size)

        assertEquals(0x0001, view.getShort(contextOffset).toInt())      // PREAUTH_INTEGRITY
        assertEquals(38, view.getShort(contextOffset + 2).toInt())      // data length
        assertEquals(1, view.getShort(contextOffset + 8).toInt())       // one hash algorithm
        assertEquals(32, view.getShort(contextOffset + 10).toInt())     // salt length
        assertEquals(0x0001, view.getShort(contextOffset + 12).toInt()) // SHA-512
    }

    @Test
    fun `the session setup points its security buffer at the blob it carries`() {
        val blob = Ntlm.negotiate()
        val body = Smb.stripFrame(Smb.smb2SessionSetupRequest(blob, messageId = 1))!!
        val view = ByteBuffer.wrap(body).order(ByteOrder.LITTLE_ENDIAN)

        assertEquals(Smb.SMB2_SESSION_SETUP, view.getShort(12).toInt())
        assertEquals(1L, view.getLong(24))                         // MessageId
        assertEquals(25, view.getShort(64).toInt())                // StructureSize
        // SecurityBufferOffset sits at body offset 12: StructureSize, Flags, SecurityMode,
        // Capabilities and Channel come first, and PreviousSessionId follows.
        val offset = view.getShort(64 + 12).toInt() and 0xFFFF
        val length = view.getShort(64 + 14).toInt() and 0xFFFF
        assertEquals(88, offset)
        assertEquals(blob.size, length)
        assertTrue(body.copyOfRange(offset, offset + length).contentEquals(blob))
    }

    @Test
    fun `the smb1 negotiate offers only NT LM 0_12`() {
        val body = Smb.stripFrame(Smb.smb1NegotiateRequest())!!
        assertEquals(0xFF, body[0].toInt() and 0xFF)
        assertTrue(String(body, Charsets.US_ASCII).contains("NT LM 0.12"))
    }

    // ---- Responses -----------------------------------------------------------------------------

    /** The question the port scan could only tell the operator to go and answer by hand. */
    @Test
    fun `signing required is read out of the negotiate response`() {
        val negotiated = Smb.parseNegotiateResponse(negotiateSigningRequired)!!
        assertEquals(0x0311, negotiated.dialect)
        assertEquals("3.1.1", negotiated.dialectName)
        assertTrue(negotiated.signingEnabled)
        assertTrue(negotiated.signingRequired)
    }

    /**
     * Signing *enabled* and signing *required* differ by one bit and by the whole finding: enabled
     * still serves a client that declines to sign, which is what a relay is.
     */
    @Test
    fun `signing enabled but not required is distinguished from signing required`() {
        val negotiated = Smb.parseNegotiateResponse(negotiateSigningEnabledOnly)!!
        assertEquals("2.1", negotiated.dialectName)
        assertTrue(negotiated.signingEnabled)
        assertFalse(negotiated.signingRequired)
    }

    @Test
    fun `the security blob is sliced from an offset measured against the header`() {
        val negotiated = Smb.parseNegotiateResponse(negotiateSigningRequired)!!
        assertEquals(13, negotiated.securityBlob.size)
        assertEquals(0x60, negotiated.securityBlob[0].toInt() and 0xFF)
    }

    @Test
    fun `an smb1 answer is recognised as smb1 and an smb2 answer as smb2`() {
        assertEquals(Smb.Family.SMB1, Smb.dialectFamilyOf(smb1NegotiateResponse))
        assertEquals(Smb.Family.SMB2, Smb.dialectFamilyOf(negotiateSigningRequired))
        assertNull(Smb.dialectFamilyOf(Smb.frame("not smb at all".toByteArray())))
    }

    /**
     * Taken from a live run: the share enumeration reported "NetrShareEnum returned nothing
     * (0x00000103)". 0x103 is STATUS_PENDING — the server saying it will answer shortly on the
     * same connection, not a refusal. Read as the answer, a result that was on its way looks like
     * an empty one.
     */
    @Test
    fun `a pending status is recognised as an interim reply rather than a refusal`() {
        assertEquals(0x00000103, Smb.STATUS_PENDING)
        val pending = Smb.frame(
            Smb.stripFrame(sessionSetupNullAccepted)!!.copyOf().also { body ->
                ByteBuffer.wrap(body).order(ByteOrder.LITTLE_ENDIAN).putInt(8, Smb.STATUS_PENDING)
            },
        )
        assertEquals(Smb.STATUS_PENDING, Smb.statusOf(pending))
        assertNotEquals(Smb.STATUS_SUCCESS, Smb.statusOf(pending))
    }

    @Test
    fun `status and null-session flags are read from the session setup response`() {
        assertEquals(Smb.STATUS_MORE_PROCESSING_REQUIRED, Smb.statusOf(sessionSetupChallenge))
        assertEquals(Smb.STATUS_SUCCESS, Smb.statusOf(sessionSetupNullAccepted))
        assertTrue(Smb.isNullSession(sessionSetupNullAccepted))
        assertFalse(Smb.isNullSession(sessionSetupChallenge))
    }

    // ---- NTLM ----------------------------------------------------------------------------------

    @Test
    fun `the ntlm negotiate carries the right signature and message type`() {
        val message = Ntlm.negotiate()
        assertEquals("NTLMSSP", String(message, 0, 7, Charsets.US_ASCII))
        assertEquals(0, message[7].toInt())
        assertEquals(1, ByteBuffer.wrap(message).order(ByteOrder.LITTLE_ENDIAN).getInt(8))
    }

    /** Anonymous means an empty NT response and the anonymous flag — never a guessed password. */
    @Test
    fun `the anonymous authenticate presents no credential of any kind`() {
        val message = Ntlm.authenticateAnonymous()
        val view = ByteBuffer.wrap(message).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals(3, view.getInt(8))
        assertEquals("LM response is one zero byte", 1, view.getShort(12).toInt())
        assertEquals("NT response is empty", 0, view.getShort(20).toInt())
        assertEquals("no domain", 0, view.getShort(28).toInt())
        assertEquals("no username", 0, view.getShort(36).toInt())
        assertEquals("no session key", 0, view.getShort(52).toInt())
        assertTrue("anonymous flag set", view.getInt(60) and 0x00000800 != 0)
    }

    /**
     * The whole reason to send an unauthenticated session setup: this all comes back before
     * anything has been proved.
     */
    @Test
    fun `the challenge discloses host, domain, dns names and os build`() {
        val challenge = Ntlm.parseChallenge(sessionSetupChallenge)!!
        assertEquals("VOIDSEC", challenge.targetName)
        assertEquals("DC01", challenge.netbiosComputer)
        assertEquals("VOIDSEC", challenge.netbiosDomain)
        assertEquals("DC01.voidsec.local", challenge.dnsComputer)
        assertEquals("voidsec.local", challenge.dnsDomain)
        assertEquals("voidsec.local", challenge.dnsForest)
        assertEquals("10.0 build 20348", challenge.osVersion)
        assertTrue(challenge.isDomainJoined)
    }

    /**
     * All three from the same live run against a Netgear router's Samba. Left alone the report
     * said "DNS domain ' '", invented a domain called DRIVE out of the machine's own name, and
     * printed "OS version 6.1 build 0" — which reads as Windows 7 about a Linux appliance whose
     * UPnP banner says ReadyDLNA on a 3.13 kernel.
     */
    @Test
    fun `a name field padded with a space is treated as absent`() {
        val challenge = Ntlm.Challenge(dnsDomain = " ", dnsComputer = " ")
        assertFalse(challenge.isDomainJoined)
        assertFalse(Ntlm.parseChallenge(sambaChallenge)!!.describe().contains("DNS domain"))
    }

    @Test
    fun `a machine that answers with its own name is not given a domain it does not have`() {
        val challenge = Ntlm.parseChallenge(sambaChallenge)!!
        assertEquals("DRIVE", challenge.netbiosComputer)
        assertTrue(challenge.isStandalone)
        assertTrue(challenge.describe().contains("Belongs to no domain"))
        assertFalse(challenge.describe().contains("Domain or workgroup"))
    }

    @Test
    fun `a version with no build number is flagged as a claim rather than a windows release`() {
        val challenge = Ntlm.parseChallenge(sambaChallenge)!!
        // The field stays a value; the caveat is a flag, so nothing has to parse prose back out.
        assertEquals("6.1", challenge.osVersion)
        assertTrue(challenge.osVersionIsCompatibilityClaim)
        assertTrue(challenge.describe().contains("no build number"))
    }

    @Test
    fun `a real windows build number is reported as one`() {
        val challenge = Ntlm.parseChallenge(sessionSetupChallenge)!!
        assertEquals("10.0 build 20348", challenge.osVersion)
        assertFalse(challenge.osVersionIsCompatibilityClaim)
        assertFalse(challenge.describe().contains("no build number"))
    }

    @Test
    fun `a workgroup machine is not reported as domain joined`() {
        val standalone = Ntlm.Challenge(
            netbiosComputer = "ROBS",
            netbiosDomain = "WORKGROUP",
            dnsComputer = "ROBS",
            dnsDomain = "ROBS",
        )
        assertFalse(standalone.isDomainJoined)
        assertTrue(standalone.describe().contains("WORKGROUP"))
    }

    @Test
    fun `a response with no ntlm challenge in it parses to null rather than throwing`() {
        assertNull(Ntlm.parseChallenge(sessionSetupNullAccepted))
        assertNull(Ntlm.parseChallenge(ByteArray(0)))
        assertNull(Ntlm.parseChallenge("NTLMSSP".toByteArray()))
    }

    /** A malformed challenge is a hostile input, not a crash. */
    @Test
    fun `fields pointing outside the message are ignored`() {
        val truncated = sessionSetupChallenge.copyOfRange(0, 140)
        val challenge = Ntlm.parseChallenge(truncated)
        // Whatever it can still read is fine; what it must not do is throw.
        assertTrue(challenge == null || challenge.dnsForest == null)
    }
}
