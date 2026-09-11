package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.exploit.UpnpWps
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class UpnpWpsTest {

    /** A description shaped like the ones consumer routers actually serve. */
    private val description = """
        <?xml version="1.0"?>
        <root xmlns="urn:schemas-upnp-org:device-1-0">
          <device>
            <deviceType>urn:schemas-wifialliance-org:device:WFADevice:1</deviceType>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:ContentDirectory:1</serviceType>
                <controlURL>/ctl/ContentDir</controlURL>
              </service>
              <service>
                <serviceType>urn:schemas-wifialliance-org:service:WFAWLANConfig:1</serviceType>
                <serviceId>urn:wifialliance-org:serviceId:WFAWLANConfig1</serviceId>
                <controlURL>/wps_control</controlURL>
                <eventSubURL>/wps_event</eventSubURL>
              </service>
            </serviceList>
          </device>
        </root>
    """.trimIndent()

    @Test
    fun `finds the wps service among others`() {
        val endpoint = UpnpWps.findWpsService(description, "http://192.168.61.1:49152/wps_device.xml")!!
        // Must pick WFAWLANConfig, not the ContentDirectory service listed before it.
        assertEquals("http://192.168.61.1:49152/wps_control", endpoint.controlUrl)
        assertTrue(endpoint.serviceType.contains("WFAWLANConfig"))
    }

    @Test
    fun `returns null when no registrar is advertised`() {
        val without = description.replace("WFAWLANConfig", "SomethingElse")
        assertNull(UpnpWps.findWpsService(without, "http://192.168.61.1:49152/d.xml"))
        assertNull(UpnpWps.findWpsService("", "http://192.168.61.1/d.xml"))
    }

    @Test
    fun `resolves relative and absolute control urls`() {
        val base = "http://192.168.61.1:49152/wps_device.xml"
        assertEquals("http://192.168.61.1:49152/wps_control", UpnpWps.resolve(base, "/wps_control"))
        assertEquals("http://192.168.61.1:49152/sub/ctl", UpnpWps.resolve(base, "sub/ctl"))
        assertEquals("http://10.0.0.1/ctl", UpnpWps.resolve(base, "http://10.0.0.1/ctl"))
    }

    @Test
    fun `builds a soap envelope naming the action`() {
        val envelope = String(UpnpWps.getDeviceInfoEnvelope(UpnpWps.SERVICE_TYPE))
        assertTrue(envelope.contains("<u:GetDeviceInfo"))
        assertTrue(envelope.contains(UpnpWps.SERVICE_TYPE))
        assertTrue(envelope.contains("s:Envelope"))
    }

    @Test
    fun `soap action header is quoted with the hash separator`() {
        assertEquals(
            "\"${UpnpWps.SERVICE_TYPE}#GetDeviceInfo\"",
            UpnpWps.soapAction(UpnpWps.SERVICE_TYPE, "GetDeviceInfo"),
        )
    }

    @Test
    fun `extracts and decodes the m1 message`() {
        val m1 = byteArrayOf(0x10, 0x4A, 0x00, 0x01, 0x10)
        val response = "<s:Body><NewDeviceInfo>${Base64.getEncoder().encodeToString(m1)}" +
            "</NewDeviceInfo></s:Body>"

        val decoded = UpnpWps.extractDeviceInfo(response)!!
        assertEquals(m1.size, decoded.size)
        assertEquals(0x10, decoded[0].toInt())
    }

    @Test
    fun `tolerates base64 wrapped across lines`() {
        val m1 = ByteArray(96) { it.toByte() }
        val wrapped = Base64.getMimeEncoder(16, "\n".toByteArray()).encodeToString(m1)
        val decoded = UpnpWps.extractDeviceInfo("<NewDeviceInfo>$wrapped</NewDeviceInfo>")
        assertNotNull(decoded)
        assertEquals(96, decoded!!.size)
    }

    @Test
    fun `a refusal is recognised as a fault, not a result`() {
        val fault = """
            <s:Envelope><s:Body><s:Fault><detail>
            <UPnPError><errorCode>401</errorCode></UPnPError>
            </detail></s:Fault></s:Body></s:Envelope>
        """.trimIndent()

        assertTrue(UpnpWps.isSoapFault(fault))
        assertEquals("401", UpnpWps.faultCode(fault))
        assertNull(UpnpWps.extractDeviceInfo(fault))
    }

    @Test
    fun `a successful response is not mistaken for a fault`() {
        val ok = "<s:Body><NewDeviceInfo>EAAB</NewDeviceInfo></s:Body>"
        assertFalse(UpnpWps.isSoapFault(ok))
    }

    @Test
    fun `malformed base64 yields null rather than throwing`() {
        assertNull(UpnpWps.extractDeviceInfo("<NewDeviceInfo>!!!not base64!!!</NewDeviceInfo>"))
    }
}
