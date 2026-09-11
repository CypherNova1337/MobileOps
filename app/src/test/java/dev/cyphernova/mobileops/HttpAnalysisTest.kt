package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.exploit.DefaultCredentials
import dev.cyphernova.mobileops.core.exploit.HttpAnalysis
import dev.cyphernova.mobileops.core.exploit.HttpResponse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class HttpAnalysisTest {

    private fun response(
        status: Int = 200,
        headers: Map<String, String> = emptyMap(),
        body: String = "",
    ) = HttpResponse(status, headers, body, 10)

    @Test
    fun `detects a basic auth challenge and reads its realm`() {
        val challenge = response(
            status = 401,
            headers = mapOf("www-authenticate" to "Basic realm=\"NETGEAR R7000\""),
        )
        assertTrue(challenge.challengesBasicAuth)
        assertEquals("NETGEAR R7000", challenge.basicAuthRealm)
    }

    @Test
    fun `a digest challenge is not treated as basic`() {
        val digest = response(status = 401, headers = mapOf("www-authenticate" to "Digest realm=\"x\""))
        assertFalse(digest.challengesBasicAuth)
        assertNull(digest.basicAuthRealm)
    }

    @Test
    fun `credentials are rejected on 401 and 403`() {
        assertFalse(HttpAnalysis.credentialsAccepted(response(status = 401)))
        assertFalse(HttpAnalysis.credentialsAccepted(response(status = 403)))
    }

    @Test
    fun `a 200 that still serves the login form is not success`() {
        // The usual way naive credential testing lies to itself.
        val stillLoggedOut = response(body = "<form><input type=\"password\" name=\"pass\"></form>")
        assertFalse(HttpAnalysis.credentialsAccepted(stillLoggedOut))
    }

    @Test
    fun `a 200 without a login form is success`() {
        assertTrue(HttpAnalysis.credentialsAccepted(response(body = "<h1>Status</h1>")))
    }

    @Test
    fun `a 200 access denied page is a rejection, not a win`() {
        // The exact false positive this produced against a live Netgear: the device answers a
        // rejected Basic auth with a friendly 200 HTML page. It has no password field, so a
        // login-form check alone scored it CRITICAL.
        val denied = response(body = "<html><body><h1>Access Denied</h1></body></html>")
        assertTrue(HttpAnalysis.looksLikeAuthFailure(denied))
        assertFalse(HttpAnalysis.credentialsAccepted(denied))
    }

    @Test
    fun `common rejection wordings are all caught`() {
        listOf(
            "Authentication failed",
            "Invalid password",
            "Incorrect password",
            "Login failed, please try again",
            "You are not authorized to view this page",
            "Session expired",
        ).forEach { text ->
            assertFalse("should reject: $text", HttpAnalysis.credentialsAccepted(response(body = text)))
        }
    }

    @Test
    fun `a genuine admin page is still accepted`() {
        // The guard must not be so eager that a real success is thrown away.
        val dashboard = response(body = "<title>RAX42 Router Status</title><h1>Connected Devices</h1>")
        assertFalse(HttpAnalysis.looksLikeAuthFailure(dashboard))
        assertTrue(HttpAnalysis.credentialsAccepted(dashboard))
    }

    @Test
    fun `page title is extracted for evidence`() {
        assertEquals(
            "NETGEAR RAX42",
            HttpAnalysis.pageTitle(response(body = "<html><head><title>NETGEAR RAX42</title></head>")),
        )
        assertNull(HttpAnalysis.pageTitle(response(body = "<h1>no title</h1>")))
    }

    @Test
    fun `page title survives attributes and newlines`() {
        val title = HttpAnalysis.pageTitle(response(body = "<title lang=\"en\">\n  Router\n</title>"))
        assertEquals("Router", title)
    }

    @Test
    fun `a redirect back to login is not success`() {
        val toLogin = response(status = 302, headers = mapOf("location" to "/login.html"))
        assertFalse(HttpAnalysis.credentialsAccepted(toLogin))

        val toDashboard = response(status = 302, headers = mapOf("location" to "/dashboard"))
        assertTrue(HttpAnalysis.credentialsAccepted(toDashboard))
    }

    @Test
    fun `a soft 404 is not mistaken for an exposed path`() {
        // Consumer routers answer everything with 200; treating that as a hit fills a report
        // with findings that are not there.
        assertTrue(HttpAnalysis.isSoftError(response(body = "<h1>404 Not Found</h1>")))
        assertTrue(HttpAnalysis.isSoftError(response(body = "The page could not be found")))
        assertFalse(HttpAnalysis.isSoftError(response(body = "<h1>Configuration</h1>")))
    }

    @Test
    fun `detects a directory listing`() {
        assertTrue(HttpAnalysis.isDirectoryListing(response(body = "<title>Index of /backup</title>")))
        assertFalse(HttpAnalysis.isDirectoryListing(response(status = 403, body = "<title>Index of /</title>")))
    }

    @Test
    fun `detects login forms across common markups`() {
        assertTrue(HttpAnalysis.looksLikeLoginForm(response(body = "<input type=\"password\">")))
        assertTrue(HttpAnalysis.looksLikeLoginForm(response(body = "<input type='password'>")))
        assertTrue(HttpAnalysis.looksLikeLoginForm(response(body = "name=\"passwd\"")))
        assertFalse(HttpAnalysis.looksLikeLoginForm(response(body = "<h1>Welcome</h1>")))
    }

    @Test
    fun `reports missing security headers and accepts frame-ancestors in csp`() {
        val bare = HttpAnalysis.missingSecurityHeaders(response())
        assertTrue(bare.contains("Content-Security-Policy"))
        assertTrue(bare.contains("X-Frame-Options"))
        assertTrue(bare.contains("Strict-Transport-Security"))

        val withCsp = HttpAnalysis.missingSecurityHeaders(
            response(headers = mapOf("content-security-policy" to "frame-ancestors 'none'")),
        )
        // CSP frame-ancestors supersedes X-Frame-Options, so demanding both would be a false finding.
        assertFalse(withCsp.contains("X-Frame-Options"))
    }

    @Test
    fun `basic auth header encodes the pair correctly`() {
        val header = HttpAnalysis.basicAuthHeader("admin", "password")
        assertTrue(header.startsWith("Basic "))
        assertEquals(
            "admin:password",
            String(Base64.getDecoder().decode(header.removePrefix("Basic "))),
        )
    }

    @Test
    fun `blank passwords survive encoding`() {
        val header = HttpAnalysis.basicAuthHeader("admin", "")
        assertEquals("admin:", String(Base64.getDecoder().decode(header.removePrefix("Basic "))))
    }
}

class DefaultCredentialsTest {

    @Test
    fun `the list stays short enough not to be a cracker`() {
        // Long lists against live appliances trip lockouts and take devices off the network,
        // which is a denial of service rather than a test result.
        assertTrue(DefaultCredentials.common.size in 10..40)
    }

    @Test
    fun `vendor pairs are tried first when the realm names one`() {
        val ordered = DefaultCredentials.forVendor("Ubiquiti")
        assertEquals("ubnt", ordered.first().username)
        // Still covers everything else afterwards.
        assertEquals(DefaultCredentials.common.size, ordered.size)
    }

    @Test
    fun `an unknown vendor falls back to the common list unchanged`() {
        assertEquals(DefaultCredentials.common, DefaultCredentials.forVendor("Nonexistent"))
        assertEquals(DefaultCredentials.common, DefaultCredentials.forVendor(null))
    }

    @Test
    fun `blank passwords are represented readably`() {
        assertEquals("admin:<blank>", DefaultCredentials.common.first { it.password.isEmpty() }.toString())
    }

    @Test
    fun `no duplicate pairs`() {
        val pairs = DefaultCredentials.common.map { it.username to it.password }
        assertEquals(pairs.size, pairs.distinct().size)
    }
}
