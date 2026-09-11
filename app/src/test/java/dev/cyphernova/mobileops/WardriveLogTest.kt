package dev.cyphernova.mobileops

import dev.cyphernova.mobileops.core.radio.WardriveLog
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WardriveLogTest {

    private fun sighting(
        name: String = "VoidSec",
        mac: String = "80:CC:9C:13:18:C4",
        type: WardriveLog.Type = WardriveLog.Type.WIFI,
    ) = WardriveLog.Sighting(
        mac = mac,
        name = name,
        authMode = "WPA2",
        firstSeenEpochMs = 1_600_000_000_000,
        channel = 10,
        rssi = -44,
        latitude = 40.7128123,
        longitude = -74.0060456,
        altitudeMetres = 12.5,
        accuracyMetres = 4.0,
        type = type,
    )

    @Test
    fun `writes the header readers key off`() {
        val csv = WardriveLog.render(listOf(sighting()), "Pixel 9 Pro XL", "15")
        val lines = csv.trim().lines()
        assertTrue(lines[0].startsWith("WigleWifi-1.4,"))
        assertTrue(lines[0].contains("model=Pixel 9 Pro XL"))
        assertEquals(
            "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude," +
                "AltitudeMeters,AccuracyMeters,Type",
            lines[1],
        )
    }

    @Test
    fun `a row carries every column in order`() {
        val row = WardriveLog.render(listOf(sighting()), "m", "15").trim().lines()[2].split(",")
        assertEquals(11, row.size)
        assertEquals("80:CC:9C:13:18:C4", row[0])
        assertEquals("VoidSec", row[1])
        assertEquals("WPA2", row[2])
        assertEquals("10", row[4])
        assertEquals("-44", row[5])
        assertEquals("40.7128123", row[6])
        assertEquals("-74.0060456", row[7])
        assertEquals("WIFI", row[10])
    }

    /** An SSID is attacker-chosen text, and a comma in it would shift every later column. */
    @Test
    fun `a comma in an ssid cannot shift the columns`() {
        val csv = WardriveLog.render(listOf(sighting(name = "ev,il\nnet")), "m", "15")
        val row = csv.trim().lines()[2].split(",")
        assertEquals(11, row.size)
        assertFalse(row[1].contains(","))
        assertFalse(row[1].contains("\n"))
    }

    @Test
    fun `timestamps are written in utc`() {
        val row = WardriveLog.render(listOf(sighting()), "m", "15").trim().lines()[2].split(",")
        assertEquals("2020-09-13 12:26:40", row[3])
    }

    @Test
    fun `wifi and bluetooth sightings share one file`() {
        val csv = WardriveLog.render(
            listOf(sighting(), sighting(type = WardriveLog.Type.BLE)),
            "m",
            "15",
        )
        assertTrue(csv.contains(",WIFI\n"))
        assertTrue(csv.contains(",BLE\n"))
    }

    @Test
    fun `an empty survey still produces a parseable file`() {
        assertEquals(2, WardriveLog.render(emptyList(), "m", "15").trim().lines().size)
    }
}
