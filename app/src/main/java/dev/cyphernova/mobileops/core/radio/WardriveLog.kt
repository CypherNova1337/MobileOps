package dev.cyphernova.mobileops.core.radio

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Writes a geolocated radio survey in the CSV layout WiGLE and Kismet both read.
 *
 * A list of APs is useful; a list of APs with coordinates is a map. Walking or driving a site
 * while logging every beacon turns a survey into coverage boundaries — where a network is
 * audible from outside the building, which is the part of a wireless assessment that is hardest
 * to argue with and impossible to produce from a single fixed position.
 *
 * Nothing here associates with anything. It is the same passive beacon listening the site survey
 * does, with the handset's own position attached to each sighting.
 */
object WardriveLog {

    /** One sighting: a radio heard at a place and a time. */
    data class Sighting(
        val mac: String,
        val name: String,
        val authMode: String,
        val firstSeenEpochMs: Long,
        val channel: Int,
        val rssi: Int,
        val latitude: Double,
        val longitude: Double,
        val altitudeMetres: Double,
        val accuracyMetres: Double,
        val type: Type,
    )

    enum class Type { WIFI, BT, BLE }

    /**
     * The header is version-stamped because the readers key off it; WigleWifi-1.4 is the layout
     * with the type column, which is what lets WiFi, classic Bluetooth and BLE share one file.
     */
    fun render(sightings: List<Sighting>, deviceModel: String, osRelease: String): String =
        buildString {
            append("WigleWifi-1.4,appRelease=1,model=")
            append(sanitise(deviceModel))
            append(",release=")
            append(sanitise(osRelease))
            append(",device=")
            append(sanitise(deviceModel))
            append(",display=,board=,brand=\n")
            append(
                "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude," +
                    "AltitudeMeters,AccuracyMeters,Type\n",
            )
            sightings.forEach { sighting ->
                append(sighting.mac).append(',')
                append(sanitise(sighting.name)).append(',')
                append(sanitise(sighting.authMode)).append(',')
                append(timestamp(sighting.firstSeenEpochMs)).append(',')
                append(sighting.channel).append(',')
                append(sighting.rssi).append(',')
                append(coordinate(sighting.latitude)).append(',')
                append(coordinate(sighting.longitude)).append(',')
                append(metres(sighting.altitudeMetres)).append(',')
                append(metres(sighting.accuracyMetres)).append(',')
                append(sighting.type.name).append('\n')
            }
        }

    /**
     * Commas and newlines in an SSID would shift every later column, and an SSID is attacker-
     * chosen text — a network can be named with a comma precisely to corrupt a log that eats it.
     */
    private fun sanitise(value: String): String =
        value.replace(',', ' ').replace('\n', ' ').replace('\r', ' ').trim()

    private fun timestamp(epochMs: Long): String = ISO.get()!!.format(Date(epochMs))

    private fun coordinate(value: Double): String = "%.7f".format(Locale.US, value)

    private fun metres(value: Double): String = "%.2f".format(Locale.US, value)

    private val ISO = object : ThreadLocal<SimpleDateFormat>() {
        override fun initialValue(): SimpleDateFormat =
            SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
                .apply { timeZone = TimeZone.getTimeZone("UTC") }
    }
}
