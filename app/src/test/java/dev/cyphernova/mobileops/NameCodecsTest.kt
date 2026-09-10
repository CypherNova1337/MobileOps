package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.discovery.Mdns
import dev.cyphernova.mobileops.core.discovery.Nbns
import dev.cyphernova.mobileops.core.discovery.Ssdp
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

class NbnsTest {

    @Test
    fun `node status request is well formed`() {
        val request = Nbns.nodeStatusRequest(0x1234)
        assertEquals(50, request.size)
        assertEquals(0x12, request[0].toInt() and 0xFF)
        assertEquals(0x34, request[1].toInt() and 0xFF)
        assertEquals(1, request[5].toInt())              // exactly one question
        assertEquals(32, request[12].toInt())            // encoded name length

        // '*' is 0x2A, so first-level encoding gives 'C' 'K'.
        assertEquals('C'.code, request[13].toInt())
        assertEquals('K'.code, request[14].toInt())
        // Padding nulls encode as 'A' 'A'.
        assertEquals('A'.code, request[15].toInt())
        assertEquals(0x21, request[request.size - 3].toInt())  // NBSTAT
    }

    /** Builds a node status response the way a Windows host answers one. */
    private fun response(vararg names: Triple<String, Int, Boolean>): ByteArray =
        ByteArrayOutputStream().apply {
            write(ByteArray(12))                          // header
            write(32); write(ByteArray(32) { 'A'.code.toByte() }); write(0)
            write(byteArrayOf(0x00, 0x21, 0x00, 0x01))    // type, class
            write(ByteArray(4))                           // ttl
            write(byteArrayOf(0x00, 0x00))                // rdlength
            write(names.size)
            names.forEach { (name, suffix, group) ->
                write(name.padEnd(15).toByteArray(Charsets.US_ASCII), 0, 15)
                write(suffix)
                write(if (group) 0x80 else 0x00)
                write(0x00)
            }
            write(ByteArray(6))                           // MAC address
        }.toByteArray()

    @Test
    fun `parses the names a host claims`() {
        val data = response(
            Triple("DESKTOP-ABC", 0x00, false),
            Triple("WORKGROUP", 0x00, true),
            Triple("DESKTOP-ABC", 0x20, false),
        )
        val names = Nbns.parseNodeStatusResponse(data)

        assertEquals(3, names.size)
        assertEquals("DESKTOP-ABC", names.first { it.isWorkstation }.name)
        assertEquals("WORKGROUP", names.first { it.isDomainOrWorkgroup }.name)
        assertTrue(names.any { it.isFileServer })
    }

    @Test
    fun `a short or empty response yields nothing rather than throwing`() {
        assertTrue(Nbns.parseNodeStatusResponse(ByteArray(0)).isEmpty())
        assertTrue(Nbns.parseNodeStatusResponse(ByteArray(20)).isEmpty())

        val data = response(Triple("HOST", 0x00, false))
        for (cut in 0 until data.size) {
            Nbns.parseNodeStatusResponse(data, cut)
        }
    }
}

class MdnsTest {

    @Test
    fun `encodes a dotted name as length prefixed labels`() {
        val encoded = Mdns.encodeName("_http._tcp.local")
        assertEquals(5, encoded[0].toInt())
        assertEquals("_http", String(encoded, 1, 5))
        assertEquals(0, encoded.last().toInt())
    }

    @Test
    fun `query targets the service enumeration name`() {
        val query = Mdns.query(Mdns.SERVICE_ENUMERATION)
        assertEquals(1, query[5].toInt())                 // one question
        assertEquals(Mdns.TYPE_PTR, query[query.size - 3].toInt())
    }

    /** A response whose answer points back at the question name, as real mDNS does. */
    private fun ptrResponse(question: String, target: String): ByteArray =
        ByteArrayOutputStream().apply {
            write(byteArrayOf(0x00, 0x00, 0x84.toByte(), 0x00))  // response, authoritative
            write(byteArrayOf(0x00, 0x01))                        // one question
            write(byteArrayOf(0x00, 0x01))                        // one answer
            write(ByteArray(4))
            write(Mdns.encodeName(question))
            write(byteArrayOf(0x00, 0x0C, 0x00, 0x01))            // PTR, IN

            write(byteArrayOf(0xC0.toByte(), 0x0C))               // pointer back to the question
            write(byteArrayOf(0x00, 0x0C, 0x00, 0x01))
            write(ByteArray(4))
            val rdata = Mdns.encodeName(target)
            write(byteArrayOf(((rdata.size shr 8) and 0xFF).toByte(), (rdata.size and 0xFF).toByte()))
            write(rdata)
        }.toByteArray()

    @Test
    fun `parses a ptr answer and follows the compression pointer`() {
        val data = ptrResponse("_services._dns-sd._udp.local", "_printer._tcp.local")
        val records = Mdns.parseResponse(data)

        assertEquals(1, records.size)
        assertEquals("_printer._tcp.local", records.single().target)
        // The answer's own name came from a pointer, so this proves the pointer was followed.
        assertEquals("_services._dns-sd._udp.local", records.single().name)
    }

    @Test
    fun `a response with no answers yields nothing`() {
        assertTrue(Mdns.parseResponse(Mdns.query("_http._tcp.local")).isEmpty())
        assertTrue(Mdns.parseResponse(ByteArray(4)).isEmpty())
    }

    @Test
    fun `a self referential pointer terminates instead of looping`() {
        // A malicious or broken responder can point a label at itself; the parser must not hang.
        val data = ByteArrayOutputStream().apply {
            write(byteArrayOf(0x00, 0x00, 0x84.toByte(), 0x00))
            write(byteArrayOf(0x00, 0x00))
            write(byteArrayOf(0x00, 0x01))
            write(ByteArray(4))
            write(byteArrayOf(0xC0.toByte(), 0x0C))       // points at itself
            write(byteArrayOf(0x00, 0x0C, 0x00, 0x01))
            write(ByteArray(4))
            write(byteArrayOf(0x00, 0x00))
        }.toByteArray()

        Mdns.parseResponse(data) // must return, not spin
    }

    @Test
    fun `every truncated prefix is survivable`() {
        val data = ptrResponse("_services._dns-sd._udp.local", "_ipp._tcp.local")
        for (cut in 0 until data.size) {
            Mdns.parseResponse(data, cut)
        }
    }
}

class SsdpTest {

    @Test
    fun `m-search carries the required headers`() {
        val text = String(Ssdp.mSearch())
        assertTrue(text.startsWith("M-SEARCH * HTTP/1.1"))
        assertTrue(text.contains("MAN: \"ssdp:discover\""))
        assertTrue(text.contains("ST: ssdp:all"))
        assertTrue(text.endsWith("\r\n\r\n"))
    }

    @Test
    fun `parses a reply and picks out the server banner`() {
        val reply = (
            "HTTP/1.1 200 OK\r\n" +
                "CACHE-CONTROL: max-age=1800\r\n" +
                "LOCATION: http://192.168.61.1:5000/rootDesc.xml\r\n" +
                "SERVER: Linux/3.14 UPnP/1.0 MiniUPnPd/1.9\r\n" +
                "ST: upnp:rootdevice\r\n" +
                "USN: uuid:abc::upnp:rootdevice\r\n\r\n"
            ).toByteArray()

        val parsed = Ssdp.parseReply(reply)!!
        assertEquals("Linux/3.14 UPnP/1.0 MiniUPnPd/1.9", parsed.server)
        assertEquals("http://192.168.61.1:5000/rootDesc.xml", parsed.location)
        assertEquals("upnp:rootdevice", parsed.searchTarget)
        assertNotNull(parsed.usn)
    }

    @Test
    fun `accepts a NOTIFY announcement as well as a search reply`() {
        val notify = "NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\nSERVER: Test/1.0\r\n\r\n".toByteArray()
        val parsed = Ssdp.parseReply(notify)!!
        assertEquals("upnp:rootdevice", parsed.searchTarget)
        assertEquals("Test/1.0", parsed.server)
    }

    @Test
    fun `rejects traffic that is not ssdp`() {
        assertNull(Ssdp.parseReply("GET / HTTP/1.1\r\n\r\n".toByteArray()))
        assertNull(Ssdp.parseReply(ByteArray(0)))
        assertFalse(Ssdp.parseReply(byteArrayOf(0x16, 0x03, 0x01)) != null)
    }
}
