package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.tls.CertificateAuthority
import dev.cyphernova.mobileops.core.tls.HttpPeek
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import javax.security.auth.x500.X500Principal

class HttpPeekTest {

    private fun request(vararg lines: String) =
        (lines.joinToString("\r\n") + "\r\n\r\n").toByteArray(Charsets.ISO_8859_1)

    @Test
    fun `parses the request line and headers`() {
        val exchange = HttpPeek.parse(
            request(
                "GET /v1/users?page=2 HTTP/1.1",
                "Host: api.example.com",
                "User-Agent: test/1.0",
            ),
        )!!

        assertEquals("GET", exchange.method)
        assertEquals("/v1/users?page=2", exchange.path)
        assertEquals("HTTP/1.1", exchange.version)
        assertEquals("api.example.com", exchange.host)
        assertEquals("https://api.example.com/v1/users?page=2", exchange.url)
        assertTrue(exchange.secrets.isEmpty())
    }

    @Test
    fun `header names are matched case insensitively`() {
        val exchange = HttpPeek.parse(request("GET / HTTP/1.1", "HOST: Example.COM"))!!
        assertEquals("Example.COM", exchange.host)
    }

    @Test
    fun `flags a bearer token without recording its value`() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret.signature"
        val exchange = HttpPeek.parse(
            request("GET / HTTP/1.1", "Host: api.example.com", "Authorization: Bearer $token"),
        )!!

        val secret = exchange.secrets.single { it.kind == "Authorization header" }
        assertTrue(secret.detail.contains("Bearer"))
        // The evidence log must describe the credential, never carry it.
        assertTrue(exchange.secrets.none { it.detail.contains(token) })
    }

    @Test
    fun `calls out basic auth for what it is`() {
        val exchange = HttpPeek.parse(
            request("GET / HTTP/1.1", "Host: x.test", "Authorization: Basic dXNlcjpwYXNz"),
        )!!
        assertTrue(exchange.secrets.single().detail.contains("base64, not encryption"))
    }

    @Test
    fun `names cookies without dumping their values`() {
        val exchange = HttpPeek.parse(
            request("GET / HTTP/1.1", "Host: x.test", "Cookie: session=abc123; theme=dark"),
        )!!
        val cookie = exchange.secrets.single { it.kind == "Cookie" }
        assertTrue(cookie.detail.contains("session"))
        assertTrue(cookie.detail.contains("2 cookie"))
        assertTrue(exchange.secrets.none { it.detail.contains("abc123") })
    }

    @Test
    fun `credentials in the query string are their own finding`() {
        val exchange = HttpPeek.parse(
            request("GET /search?q=cats&api_key=SECRET123 HTTP/1.1", "Host: x.test"),
        )!!
        val secret = exchange.secrets.single { it.kind == "Credential in URL" }
        assertTrue(secret.detail.contains("api_key"))
        assertTrue(secret.detail.contains("server logs"))
        assertTrue(exchange.secrets.none { it.detail.contains("SECRET123") })
    }

    @Test
    fun `custom credential headers are detected`() {
        val exchange = HttpPeek.parse(
            request("POST /v1 HTTP/1.1", "Host: x.test", "X-Api-Key: abc", "X-Session-Token: def"),
        )!!
        assertEquals(2, exchange.secrets.count { it.kind == "Credential header" })
    }

    @Test
    fun `rejects traffic that is not http`() {
        assertNull(HttpPeek.parse(byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x05)))
        assertNull(HttpPeek.parse("NOTAVERB / HTTP/1.1\r\n\r\n".toByteArray()))
        assertNull(HttpPeek.parse(ByteArray(0)))
    }

    @Test
    fun `survives headers split across the buffer boundary`() {
        // The relay hands over whatever arrived first; a partial header block must not throw.
        val partial = "GET / HTTP/1.1\r\nHost: x.test\r\nAuthorization: Bear".toByteArray()
        assertNotNull(HttpPeek.parse(partial))
    }
}

class CertificateAuthorityTest {

    @get:Rule val folder = TemporaryFolder()

    private fun authority() = CertificateAuthority(folder.newFolder("tls"))

    @Test
    fun `generates a usable ca certificate`() = runBlocking {
        val ca = authority()
        val certificate = ca.initialise()

        assertTrue(ca.isReady)
        assertTrue(certificate.subjectX500Principal.name.contains(CertificateAuthority.CA_COMMON_NAME))
        // basicConstraints CA:true is what makes it able to sign anything at all.
        assertTrue("must be a CA", certificate.basicConstraints >= 0)
        assertTrue("must allow keyCertSign", certificate.keyUsage[5])
        certificate.checkValidity()
    }

    @Test
    fun `the ca is self signed`() = runBlocking {
        val certificate = authority().initialise()
        assertEquals(certificate.subjectX500Principal, certificate.issuerX500Principal)
        certificate.verify(certificate.publicKey)
    }

    @Test
    fun `mints a leaf that is signed by the ca and names the host`() = runBlocking {
        val ca = authority()
        val root = ca.initialise()

        val leaf = ca.leafFor("example.com")!!
        leaf.certificate.verify(root.publicKey)

        assertEquals(X500Principal("CN=example.com"), leaf.certificate.subjectX500Principal)
        assertEquals(root.subjectX500Principal, leaf.certificate.issuerX500Principal)
        assertTrue("leaf must not be a CA", leaf.certificate.basicConstraints < 0)

        // Modern clients match on SAN and ignore CN entirely, so this is the field that decides
        // whether the substituted certificate is accepted.
        val sans = leaf.certificate.subjectAlternativeNames!!.map { it[1] as String }
        assertTrue(sans.contains("example.com"))
    }

    @Test
    fun `an ip destination gets an ip san rather than a dns one`() = runBlocking {
        val ca = authority()
        ca.initialise()
        val leaf = ca.leafFor("192.168.1.1")!!
        val entry = leaf.certificate.subjectAlternativeNames!!.single()
        assertEquals(7, entry[0]) // GeneralName.iPAddress
        assertEquals("192.168.1.1", entry[1])
    }

    @Test
    fun `leaves are cached per host`() = runBlocking {
        val ca = authority()
        ca.initialise()
        // A fresh certificate per connection would break session resumption and stand out.
        assertSame(ca.leafFor("example.com"), ca.leafFor("example.com"))
    }

    @Test
    fun `the ca survives a restart rather than regenerating`() = runBlocking {
        val directory = folder.newFolder("persisted")
        val first = CertificateAuthority(directory).initialise()
        val second = CertificateAuthority(directory).initialise()
        // Regenerating would silently invalidate a CA the operator had already installed.
        assertEquals(first.serialNumber, second.serialNumber)
        assertEquals(first, second)
    }

    @Test
    fun `exports pem that a device can import`() = runBlocking {
        val ca = authority()
        ca.initialise()
        val pem = ca.exportPem()!!

        assertTrue(pem.startsWith("-----BEGIN CERTIFICATE-----"))
        assertTrue(pem.trimEnd().endsWith("-----END CERTIFICATE-----"))
        assertTrue(ca.exportedCertificateFile.exists())
    }

    @Test
    fun `reports the filename the system trust store keys on`() = runBlocking {
        val ca = authority()
        ca.initialise()
        val name = ca.systemTrustStoreName()!!
        assertTrue(name.matches(Regex("^[0-9a-f]{8}\\.0$")))
    }

    @Test
    fun `no leaf is issued before the ca exists`() {
        assertNull(authority().leafFor("example.com"))
    }
}
