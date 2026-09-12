package dev.cyphernova.mobileops.modules.tier0

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.os.Build
import android.os.Looper
import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleCategory
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule
import dev.cyphernova.mobileops.core.radio.WardriveLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicReference

/**
 * Logs every AP heard against the handset's position, producing a map rather than a list.
 *
 * A site survey taken standing still answers "what is here". Walking the perimeter with this
 * running answers the question a wireless assessment is actually about: how far outside the
 * building the network is audible, and from where. That is the finding a client cannot argue
 * with — a coordinate in the public car park with a usable signal from the internal SSID.
 *
 * The output is the CSV layout WiGLE and Kismet both read, so the track drops straight into
 * mapping tools. Nothing associates with anything; this is the same passive beacon listening the
 * site survey does, with coordinates attached.
 */
class WardriveModule : PentestModule {
    override val id = "t0.wifi.wardrive"
    override val title = "Geolocated survey (wardrive)"
    override val description =
        "Logs every AP heard against GPS position over a rolling sweep and writes a WiGLE-format " +
            "CSV. Walk the perimeter with this running to map where a network leaks to."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.PASSIVE
    override val category = ModuleCategory.WIRELESS
    override val requiredPermissions = listOf(Manifest.permission.ACCESS_FINE_LOCATION)

    @SuppressLint("MissingPermission")
    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val androidContext = context.androidContext
        val radio = WifiRadio(androidContext)
        if (!radio.isWifiEnabled) {
            return ModuleOutcome.Blocked("WiFi must be on to hear beacons, though nothing is joined.")
        }

        val locations = androidContext.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
            ?: return ModuleOutcome.Blocked("No location service on this device.")

        if (!locations.isProviderEnabled(LocationManager.GPS_PROVIDER) &&
            !locations.isProviderEnabled(LocationManager.NETWORK_PROVIDER)
        ) {
            return ModuleOutcome.Blocked(
                "Location is switched off device-wide. Without coordinates this is just a site " +
                    "survey, which the RF survey module already does.",
            )
        }

        // The listener fires on the main looper while the sweep runs on a background
        // dispatcher, so the handoff needs to be across threads rather than a captured local.
        val fix = AtomicReference<Location?>(null)
        val listener = LocationListener { location -> fix.set(location) }

        val subscribed = runCatching {
            listOf(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER)
                .filter(locations::isProviderEnabled)
                .forEach { provider ->
                    locations.requestLocationUpdates(
                        provider,
                        FIX_INTERVAL_MS,
                        0f,
                        listener,
                        Looper.getMainLooper(),
                    )
                }
        }
        if (subscribed.isFailure) {
            return ModuleOutcome.Failed("Could not subscribe to location updates.")
        }

        // A last known fix gets the first sweep coordinates while GPS is still acquiring, which
        // otherwise takes most of a minute outdoors and never completes indoors.
        if (fix.get() == null) {
            runCatching {
                listOf(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER)
                    .filter(locations::isProviderEnabled)
                    .firstNotNullOfOrNull(locations::getLastKnownLocation)
            }.getOrNull()?.let(fix::set)
        }

        // Keyed by BSSID and rounded position: the same AP heard from two places is two rows,
        // which is the entire point — one row per AP would throw the coverage map away.
        val sightings = linkedMapOf<String, WardriveLog.Sighting>()
        var unlocated = 0

        try {
            repeat(SWEEPS) {
                radio.requestScan()
                delay(SWEEP_INTERVAL_MS)

                val here = fix.get()
                if (here == null) {
                    unlocated++
                    return@repeat
                }

                radio.latestResults().forEach { ap ->
                    if (ap.bssid.isBlank()) return@forEach
                    val key = "${ap.bssid}@${round(here.latitude)},${round(here.longitude)}"
                    sightings.getOrPut(key) {
                        WardriveLog.Sighting(
                            mac = ap.bssid.uppercase(),
                            name = ap.ssid,
                            authMode = ApSecurityAnalyser.analyse(ap).encryption.label,
                            firstSeenEpochMs = System.currentTimeMillis(),
                            channel = ap.channel,
                            rssi = ap.rssiDbm,
                            latitude = here.latitude,
                            longitude = here.longitude,
                            altitudeMetres = if (here.hasAltitude()) here.altitude else 0.0,
                            accuracyMetres = if (here.hasAccuracy()) here.accuracy.toDouble() else 0.0,
                            type = WardriveLog.Type.WIFI,
                        )
                    }
                }
            }
        } finally {
            runCatching { locations.removeUpdates(listener) }
        }

        if (sightings.isEmpty()) {
            return ModuleOutcome.Failed(
                if (unlocated > 0) {
                    "No position fix was obtained in $SWEEPS sweep(s). GPS needs sky view; indoors " +
                        "only the network provider will resolve, and only with mobile data on."
                } else {
                    "No APs heard."
                },
            )
        }

        val rows = sightings.values.toList()
        val file = write(androidContext, rows)
        val distinctAps = rows.map { it.mac }.distinct().size
        val positions = rows.map { it.latitude to it.longitude }.distinct().size

        emit(
            Finding(
                moduleId = id,
                observedAtEpochMs = System.currentTimeMillis(),
                severity = Severity.INFO,
                title = "Wardrive: $distinctAps AP(s) across $positions position(s)",
                subject = file.name,
                detail = "${rows.size} geolocated sighting(s) of $distinctAps distinct AP(s) from " +
                    "$positions position(s), written to ${file.absolutePath} in WiGLE CSV format. " +
                    "Import it into a mapping tool to see the coverage footprint." +
                    if (unlocated > 0) " $unlocated sweep(s) had no fix and were dropped." else "",
                data = mapOf(
                    "csv_path" to file.absolutePath,
                    "sightings" to rows.size.toString(),
                    "distinct_aps" to distinctAps.toString(),
                    "positions" to positions.toString(),
                    "sweeps_without_fix" to unlocated.toString(),
                ),
            ),
        )

        emitFurthest(rows, emit)

        return ModuleOutcome.Completed(
            "$distinctAps AP(s) logged from $positions position(s) into ${file.name}.",
        )
    }

    /**
     * The strongest reading taken furthest from where the sweep started is the leakage finding.
     * Reported separately because it is the row anyone reading the report actually wants.
     */
    private suspend fun emitFurthest(
        rows: List<WardriveLog.Sighting>,
        emit: suspend (Finding) -> Unit,
    ) {
        val origin = rows.first()
        val furthest = rows
            .filter { it.rssi != 0 && it.rssi > USABLE_RSSI }
            .maxByOrNull { distanceMetres(origin, it) }
            ?: return
        val metres = distanceMetres(origin, furthest)
        if (metres < MEANINGFUL_DISTANCE_M) return

        emit(
            Finding(
                moduleId = id,
                observedAtEpochMs = System.currentTimeMillis(),
                severity = Severity.LOW,
                title = "Usable signal ${metres.toInt()} m from the start point",
                subject = furthest.name.ifBlank { furthest.mac },
                detail = "'${furthest.name.ifBlank { "<hidden>" }}' (${furthest.mac}, " +
                    "${furthest.authMode}) was still readable at ${furthest.rssi} dBm " +
                    "${metres.toInt()} m from where this sweep began, at " +
                    "${"%.5f".format(Locale.US, furthest.latitude)}, " +
                    "${"%.5f".format(Locale.US, furthest.longitude)}. An attacker does not need " +
                    "to be in the building.",
                data = mapOf(
                    "bssid" to furthest.mac,
                    "ssid" to furthest.name,
                    "distance_m" to metres.toInt().toString(),
                    "rssi" to furthest.rssi.toString(),
                    "latitude" to "%.6f".format(Locale.US, furthest.latitude),
                    "longitude" to "%.6f".format(Locale.US, furthest.longitude),
                ),
            ),
        )
    }

    private suspend fun write(
        context: Context,
        rows: List<WardriveLog.Sighting>,
    ): File = withContext(Dispatchers.IO) {
        val directory = File(context.filesDir, "wardrive").apply { mkdirs() }
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
        val file = File(directory, "wardrive-$stamp.csv")
        file.writeText(WardriveLog.render(rows, Build.MODEL, Build.VERSION.RELEASE))
        file
    }

    /** Rounding to roughly ten metres keeps a stationary operator from writing a row per sweep. */
    private fun round(value: Double): String = "%.4f".format(Locale.US, value)

    /**
     * Equirectangular approximation. Over the hundreds of metres a walked survey covers it is
     * accurate to well under a metre, and it avoids the trigonometry of a full haversine for a
     * number that is reported rounded anyway.
     */
    private fun distanceMetres(from: WardriveLog.Sighting, to: WardriveLog.Sighting): Double {
        val latRadians = Math.toRadians((from.latitude + to.latitude) / 2)
        val dLat = Math.toRadians(to.latitude - from.latitude) * EARTH_RADIUS_M
        val dLon = Math.toRadians(to.longitude - from.longitude) * EARTH_RADIUS_M * Math.cos(latRadians)
        return Math.hypot(dLat, dLon)
    }

    private companion object {
        const val SWEEPS = 4
        const val SWEEP_INTERVAL_MS = 8_000L
        const val FIX_INTERVAL_MS = 2_000L
        const val EARTH_RADIUS_M = 6_371_000.0

        /** Below about -85 dBm a network is audible but not usefully associable. */
        const val USABLE_RSSI = -85
        const val MEANINGFUL_DISTANCE_M = 15.0
    }
}
