package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.tls.SniParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

class SniParserTest {

    /** Builds a real ClientHello so the parser is tested against the wire format, not a mock. */
    private fun clientHello(
        hostname: String?,
        sessionIdLength: Int = 0,
        cipherSuiteCount: Int = 1,
    ): ByteArray {
        val body = ByteArrayOutputStream()
        body.write(byteArrayOf(0x03, 0x03))          // client_version TLS 1.2
        body.write(ByteArray(32) { it.toByte() })    // random

        body.write(sessionIdLength)                  // legacy_session_id
        body.write(ByteArray(sessionIdLength))

        val cipherBytes = cipherSuiteCount * 2
        body.write((cipherBytes shr 8) and 0xFF)
        body.write(cipherBytes and 0xFF)
        repeat(cipherSuiteCount) { body.write(byteArrayOf(0x00, 0x2F)) }

        body.write(1)                                // compression methods
        body.write(0)

        val extensions = ByteArrayOutputStream()
        if (hostname != null) {
            val host = hostname.toByteArray(Charsets.US_ASCII)
            val entry = ByteArrayOutputStream().apply {
                write(0x00)                          // name_type = host_name
                write((host.size shr 8) and 0xFF)
                write(host.size and 0xFF)
                write(host)
            }.toByteArray()

            val list = ByteArrayOutputStream().apply {
                write((entry.size shr 8) and 0xFF)
                write(entry.size and 0xFF)
                write(entry)
            }.toByteArray()

            extensions.write(byteArrayOf(0x00, 0x00)) // extension_type = server_name
            extensions.write((list.size shr 8) and 0xFF)
            extensions.write(list.size and 0xFF)
            extensions.write(list)
        } else {
            // A supported_versions extension, so "no SNI" is not the same as "no extensions".
            extensions.write(byteArrayOf(0x00, 0x2B, 0x00, 0x03, 0x02, 0x03, 0x04))
        }

        val extensionBytes = extensions.toByteArray()
        body.write((extensionBytes.size shr 8) and 0xFF)
        body.write(extensionBytes.size and 0xFF)
        body.write(extensionBytes)

        val bodyBytes = body.toByteArray()
        val handshake = ByteArrayOutputStream().apply {
            write(0x01)                              // ClientHello
            write((bodyBytes.size shr 16) and 0xFF)
            write((bodyBytes.size shr 8) and 0xFF)
            write(bodyBytes.size and 0xFF)
            write(bodyBytes)
        }.toByteArray()

        return ByteArrayOutputStream().apply {
            write(0x16)                              // handshake record
            write(byteArrayOf(0x03, 0x01))           // legacy record version
            write((handshake.size shr 8) and 0xFF)
            write(handshake.size and 0xFF)
            write(handshake)
        }.toByteArray()
    }

    @Test
    fun `extracts the hostname from a well formed client hello`() {
        assertEquals("example.com", SniParser.extractHostname(clientHello("example.com")))
    }

    @Test
    fun `handles a session id and multiple cipher suites`() {
        // Both are variable-length fields ahead of the extensions; mis-skipping either puts the
        // reader out of alignment and the hostname comes back as garbage rather than null.
        val hello = clientHello("api.internal.test", sessionIdLength = 32, cipherSuiteCount = 17)
        assertEquals("api.internal.test", SniParser.extractHostname(hello))
    }

    @Test
    fun `returns null when no sni extension is present`() {
        assertNull(SniParser.extractHostname(clientHello(null)))
    }

    @Test
    fun `returns null for a truncated record rather than throwing`() {
        val hello = clientHello("example.com")
        for (cut in 1 until hello.size) {
            // Every prefix must be survivable: this parses the first bytes of an untrusted peer.
            SniParser.extractHostname(hello, cut)
        }
        assertNull(SniParser.extractHostname(hello, 10))
    }

    @Test
    fun `rejects non handshake traffic`() {
        assertNull(SniParser.extractHostname("GET / HTTP/1.1\r\n\r\n".toByteArray()))
        assertNull(SniParser.extractHostname(ByteArray(0)))
    }

    @Test
    fun `rejects a hostname carrying non printable bytes`() {
        // A control byte here would otherwise flow straight into a certificate subject.
        assertNull(SniParser.extractHostname(clientHello("bad\u0001host")))
    }

    @Test
    fun `looksLikeTls distinguishes a handshake from plaintext`() {
        assertTrue(SniParser.looksLikeTls(clientHello("example.com")))
        assertFalse(SniParser.looksLikeTls("GET / HTTP/1.1".toByteArray()))
        assertFalse(SniParser.looksLikeTls(ByteArray(2)))
    }

    @Test
    fun `long hostnames survive the two byte length field`() {
        val host = "a".repeat(200) + ".example.com"
        assertEquals(host, SniParser.extractHostname(clientHello(host)))
    }
}
