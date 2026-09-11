package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.iot.DeviceFingerprint
import dev.cyphernova.mobileops.core.iot.DeviceFingerprint.Category
import dev.cyphernova.mobileops.core.iot.DeviceFingerprint.Confidence
import dev.cyphernova.mobileops.core.iot.IotPorts
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceFingerprintTest {

    private fun evidence(
        ports: Set<Int> = emptySet(),
        names: List<String> = emptyList(),
        vendor: String? = null,
        banners: Map<Int, String> = emptyMap(),
    ) = DeviceFingerprint.Evidence(
        address = "10.0.0.5",
        openPorts = ports,
        banners = banners,
        names = names,
        macVendor = vendor,
    )

    @Test
    fun `a dicom port identifies an imaging node`() {
        val verdict = DeviceFingerprint.classify(evidence(ports = setOf(104)))
        assertEquals(Category.MEDICAL_IMAGING, verdict.category)
        assertEquals(Confidence.STRONG, verdict.confidence)
        assertTrue(verdict.significance.contains("AE title"))
    }

    @Test
    fun `each equipment protocol lands in its own category`() {
        mapOf(
            2575 to Category.MEDICAL_INTERFACE,
            502 to Category.INDUSTRIAL_CONTROL,
            47808 to Category.BUILDING_CONTROL,
            554 to Category.IP_CAMERA,
            1883 to Category.IOT_BROKER,
            5683 to Category.IOT_SENSOR,
            9100 to Category.PRINTER,
            5060 to Category.VOIP,
        ).forEach { (port, expected) ->
            assertEquals("port $port", expected, DeviceFingerprint.classify(evidence(setOf(port))).category)
        }
    }

    /**
     * A host can be several things at once. The one that decides how it is handled — and how
     * much it matters on a site like this — has to win over the web server it also runs.
     */
    @Test
    fun `equipment outranks a general-purpose service on the same host`() {
        val verdict = DeviceFingerprint.classify(evidence(ports = setOf(80, 443, 22, 104)))
        assertEquals(Category.MEDICAL_IMAGING, verdict.category)
    }

    @Test
    fun `a protocol port outranks a contradicting name`() {
        // Called a printer, answering Modbus. What it speaks is the fact.
        val verdict = DeviceFingerprint.classify(
            evidence(ports = setOf(502), names = listOf("LaserJet-4th-floor")),
        )
        assertEquals(Category.INDUSTRIAL_CONTROL, verdict.category)
    }

    @Test
    fun `names identify equipment when no port gives it away`() {
        val verdict = DeviceFingerprint.classify(evidence(names = listOf("ALARIS-PUMP-114")))
        assertEquals(Category.PATIENT_MONITORING, verdict.category)
        assertEquals(Confidence.INFERRED, verdict.confidence)
        assertTrue(verdict.significance.contains("patient-safety"))
    }

    @Test
    fun `vendor names in banners are enough to classify`() {
        assertEquals(
            Category.BUILDING_CONTROL,
            DeviceFingerprint.classify(evidence(banners = mapOf(80 to "Niagara Web Server"))).category,
        )
        assertEquals(
            Category.IP_CAMERA,
            DeviceFingerprint.classify(evidence(vendor = "Hikvision Digital Technology")).category,
        )
    }

    /**
     * The fragility judgement is the one with real-world consequences: on a live site, scanning
     * a delicate device hard is an outage rather than a finding.
     */
    @Test
    fun `equipment is marked fragile so the scanner backs off`() {
        listOf(104, 502, 47808, 2575).forEach { port ->
            assertEquals(
                "port $port",
                IotPorts.Fragility.FRAGILE,
                DeviceFingerprint.classify(evidence(setOf(port))).fragility,
            )
        }
    }

    @Test
    fun `a name that points at equipment is treated as delicate even with no port evidence`() {
        val verdict = DeviceFingerprint.classify(evidence(names = listOf("chiller-plant-bms")))
        assertEquals(Category.BUILDING_CONTROL, verdict.category)
        assertNotEquals(IotPorts.Fragility.ROBUST, verdict.fragility)
    }

    @Test
    fun `the most cautious fragility on a host wins`() {
        // A web server alongside a BACnet stack is still handled as BACnet.
        assertEquals(
            IotPorts.Fragility.FRAGILE,
            DeviceFingerprint.classify(evidence(setOf(631, 47808))).fragility,
        )
        assertEquals(IotPorts.Fragility.EMBEDDED, IotPorts.fragilityAcross(listOf(631, 9100)))
        assertEquals(IotPorts.Fragility.ROBUST, IotPorts.fragilityAcross(emptyList()))
    }

    @Test
    fun `ordinary hosts fall back to server or endpoint rather than being called equipment`() {
        assertEquals(Category.SERVER, DeviceFingerprint.classify(evidence(setOf(22, 3306))).category)
        assertEquals(Category.NETWORK_DEVICE, DeviceFingerprint.classify(evidence(setOf(161))).category)
        assertEquals(Category.UNKNOWN, DeviceFingerprint.classify(evidence()).category)
    }

    @Test
    fun `every verdict explains what it was based on`() {
        listOf(
            evidence(setOf(104)),
            evidence(names = listOf("mirth-connect")),
            evidence(setOf(22)),
            evidence(),
        ).forEach { assertTrue(DeviceFingerprint.classify(it).basis.isNotBlank()) }
    }

    @Test
    fun `the port catalogue records significance for everything it knows`() {
        assertTrue(IotPorts.allPorts.isNotEmpty())
        IotPorts.allPorts.forEach { port ->
            val service = IotPorts.serviceAt(port)!!
            assertTrue("port $port", service.significance.isNotBlank())
            assertTrue("port $port", service.name.isNotBlank())
        }
        assertTrue(IotPorts.portsFor(IotPorts.Domain.MEDICAL).contains(104))
    }
}
