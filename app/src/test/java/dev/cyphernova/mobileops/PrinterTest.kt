package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.printer.Ipp
import dev.cyphernova.mobileops.core.printer.Pjl
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PrinterTest {

    private fun hex(text: String): ByteArray =
        text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    /** A Get-Printer-Attributes reply shaped like the Lexmark MS312dn on this network. */
    private val ippResponse = hex(
        "010100000000000101470012617474726962757465732d6368617273657400057574662d3848001b6174" +
        "74726962757465732d6e61747572616c2d6c616e67756167650005656e2d7573044100167072696e7465" +
        "722d6d616b652d616e642d6d6f64656c000f4c65786d61726b204d53333132646e41001f7072696e7465" +
        "722d6669726d776172652d737472696e672d76657273696f6e000b4e48352e43592e4e35343341001070" +
        "72696e7465722d6c6f636174696f6e000e326e6420666c6f6f72206561737441000c7072696e7465722d" +
        "696e666f00074d53333132646e4500157072696e7465722d7572692d737570706f727465640021697070" +
        "733a2f2f3139322e3136382e36312e363a3434332f6970702f7072696e7445000000206970703a2f2f31" +
        "39322e3136382e36312e363a3633312f6970702f7072696e7444001c7572692d61757468656e74696361" +
        "74696f6e2d737570706f7274656400046e6f6e65440000001472657175657374696e672d757365722d6e" +
        "616d652100107175657565642d6a6f622d636f756e740004000000032200197072696e7465722d69732d" +
        "616363657074696e672d6a6f627300010103",
    )

    // ---- IPP -----------------------------------------------------------------------------------

    @Test
    fun `the request is big-endian and names the operation and the printer`() {
        val request = Ipp.getPrinterAttributesRequest("ipp://192.168.61.6/ipp/print")
        assertEquals(0x01, request[0].toInt())            // version 1.1
        assertEquals(0x01, request[1].toInt())
        assertEquals(0x00, request[2].toInt())            // Get-Printer-Attributes is 0x000B
        assertEquals(0x0B, request[3].toInt())
        assertEquals(0x01, request[8].toInt())            // operation-attributes-tag
        assertEquals(0x03, request.last().toInt())        // end-of-attributes-tag
        val text = String(request, Charsets.US_ASCII)
        assertTrue(text.contains("attributes-charset"))
        assertTrue(text.contains("ipp://192.168.61.6/ipp/print"))
    }

    @Test
    fun `the printer identifies itself down to the firmware`() {
        val attributes = Ipp.parse(ippResponse)!!
        assertTrue(attributes.isSuccess)
        assertEquals("Lexmark MS312dn", attributes.makeAndModel)
        assertEquals("NH5.CY.N543", attributes.firmware)
        assertEquals("2nd floor east", attributes.location)
        assertEquals(3, attributes.queuedJobs)
    }

    /**
     * A zero-length name means "another value for the attribute before me". Read as a fresh
     * attribute, the second URI would be filed under an empty name and the cleartext one would
     * never be noticed.
     */
    @Test
    fun `an additional value is attached to the attribute it continues`() {
        val attributes = Ipp.parse(ippResponse)!!
        assertEquals(2, attributes.values["printer-uri-supported"]?.size)
        assertTrue(attributes.hasCleartextUri)
        assertEquals(2, attributes.values["uri-authentication-supported"]?.size)
    }

    @Test
    fun `a printer saying it needs no credential is recognised`() {
        assertTrue(Ipp.parse(ippResponse)!!.acceptsUnauthenticated)
        val requiresAuth = Ipp.Attributes(0, mapOf("uri-authentication-supported" to listOf("basic")))
        assertFalse(requiresAuth.acceptsUnauthenticated)
    }

    @Test
    fun `integers and booleans are decoded from their bytes, not read as text`() {
        val attributes = Ipp.parse(ippResponse)!!
        assertEquals("3", attributes.first("queued-job-count"))
        assertEquals("true", attributes.first("printer-is-accepting-jobs"))
    }

    @Test
    fun `a truncated or empty response parses to nothing rather than throwing`() {
        assertNull(Ipp.parse(ByteArray(0)))
        for (length in 8..ippResponse.size step 11) {
            Ipp.parse(ippResponse.copyOfRange(0, length))
        }
    }

    // ---- PJL -----------------------------------------------------------------------------------

    private val esc = "\u001B"
    private val ff = "\u000C"

    /** A reply in the shape a printer sends: echoed command, values, form feed. */
    private val pjlReply =
        "$esc%-12345X@PJL INFO ID\r\n\"Lexmark MS312dn\"\r\n$ff" +
            "@PJL INFO VARIABLES\r\n" +
            "PASSWORD=0 [2 RANGE]\r\n" +
            "SMTPSERVER=\"mail.voidsec.local\"\r\n" +
            "DISKLOCK=OFF\r\n" +
            "COPIES=1 [2 RANGE]\r\n$ff" +
            "@PJL FSDIRLIST NAME=\"0:\\\" ENTRY=1\r\n" +
            ". TYPE=DIR\r\n" +
            ".. TYPE=DIR\r\n" +
            "saveDevice TYPE=DIR\r\n" +
            "held_job_0417.ps TYPE=FILE SIZE=284117\r\n$ff"

    @Test
    fun `the inventory job is bracketed by the exit sequence and asks only read commands`() {
        val request = String(Pjl.inventoryRequest(), Charsets.US_ASCII)
        assertTrue(request.startsWith(Pjl.UEL))
        assertTrue(request.endsWith(Pjl.UEL))
        assertTrue(request.contains("@PJL INFO ID"))
        assertTrue(request.contains("@PJL FSDIRLIST"))

        // The line this module must never cross: nothing that alters the device.
        listOf("FSDELETE", "FSDOWNLOAD", "DEFAULT ", "RDYMSG", "SET ", "JOB", "OPMSG").forEach {
            assertFalse("must not send $it", request.contains(it))
        }
    }

    @Test
    fun `each answered query is separated at the form feed`() {
        val blocks = Pjl.parse(pjlReply)
        assertEquals(3, blocks.size)
        assertEquals("Lexmark MS312dn", Pjl.modelIn(blocks))
    }

    @Test
    fun `settings are read as name and value with the permitted range dropped`() {
        val settings = Pjl.settingsIn(Pjl.parse(pjlReply))
        assertEquals("0", settings["PASSWORD"])
        assertEquals("1", settings["COPIES"])
        assertEquals("\"mail.voidsec.local\"", settings["SMTPSERVER"])
    }

    /** The point of reading the settings at all: which of them lead somewhere else. */
    @Test
    fun `settings that name a credential or another server are singled out`() {
        val notable = Pjl.notableSettings(Pjl.settingsIn(Pjl.parse(pjlReply)))
        assertTrue(notable.containsKey("PASSWORD"))
        assertTrue(notable.containsKey("SMTPSERVER"))
        assertTrue(notable.containsKey("DISKLOCK"))
        assertFalse("a copy count is not a finding", notable.containsKey("COPIES"))
    }

    @Test
    fun `the storage listing skips the directory's own entries`() {
        val files = Pjl.filesIn(Pjl.parse(pjlReply))
        assertEquals(listOf("saveDevice", "held_job_0417.ps"), files.map { it.name })
        assertTrue(files.first { it.name == "saveDevice" }.isDirectory)
        assertEquals(284117L, files.first { it.name.endsWith(".ps") }.sizeBytes)
    }

    /** A device that declines the listing is behaving correctly, not producing a finding. */
    @Test
    fun `a refused listing yields no entries`() {
        val refused = "@PJL FSDIRLIST NAME=\"0:\\\"\r\nFILEERROR=63018\r\n$ff"
        assertTrue(Pjl.filesIn(Pjl.parse(refused)).isEmpty())
    }

    @Test
    fun `an empty or garbled reply yields nothing rather than throwing`() {
        assertTrue(Pjl.parse("").isEmpty())
        assertTrue(Pjl.parse("\u0000\u0001 nonsense").isEmpty())
        assertNull(Pjl.modelIn(emptyList()))
        assertTrue(Pjl.settingsIn(emptyList()).isEmpty())
    }
}
