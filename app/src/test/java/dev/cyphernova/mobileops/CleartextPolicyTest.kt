package dev.cyphernova.mobileops

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Guards the one setting that decides whether this app can talk to LAN appliances at all.
 *
 * Since API 28 Android blocks cleartext HTTP by default, and it blocks it inside the HTTP stack
 * rather than at the socket — the request throws before a packet leaves the handset, with a
 * message about policy rather than about the network. Every plain-HTTP path in this app failed
 * that way, silently, for as long as the manifest said nothing: the WPS registrar description on
 * port 49152, IPP on 631, and the web audit of ports 80 and 8080, which is to say every router
 * and printer admin page on the segment.
 *
 * It cost hours of chasing symptoms in four modules. A missing attribute in a manifest is exactly
 * the kind of thing that regresses without anyone noticing, so it is asserted here rather than
 * left to be rediscovered the same way.
 */
class CleartextPolicyTest {

    private val manifest = File("src/main/AndroidManifest.xml")
    private val config = File("src/main/res/xml/network_security_config.xml")

    @Test
    fun `the manifest permits cleartext and points at the network security config`() {
        assertTrue("manifest not found at ${manifest.absolutePath}", manifest.exists())
        val text = manifest.readText()
        assertTrue(
            "cleartext HTTP must be permitted or every plain-HTTP probe fails before it is sent",
            text.contains("android:usesCleartextTraffic=\"true\""),
        )
        assertTrue(
            "the network security config must be referenced",
            text.contains("android:networkSecurityConfig=\"@xml/network_security_config\""),
        )
    }

    @Test
    fun `the network security config exists and permits cleartext`() {
        assertTrue("config not found at ${config.absolutePath}", config.exists())
        val text = config.readText()
        assertTrue(text.contains("cleartextTrafficPermitted=\"true\""))
        // LAN appliances ship self-signed certificates; the interception path needs a user CA.
        assertTrue(text.contains("src=\"user\""))
    }
}
