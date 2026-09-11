package dev.cyphernova.mobileops.modules.tier0

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Build
import dev.cyphernova.mobileops.core.ble.BleVendors
import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleCategory
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule
import kotlinx.coroutines.delay
import java.util.concurrent.ConcurrentHashMap

/**
 * Enumerates Bluetooth Low Energy devices in range.
 *
 * BLE is the reconnaissance surface most network-focused tooling ignores, and on a handset it is
 * entirely free: every phone, wearable, tracker, sensor, lock and television in range advertises
 * continuously, unencrypted, to anything listening. No pairing, no connection, no network of any
 * kind — which makes this work in a lobby, a car park, or a building with no WiFi at all.
 *
 * What it yields that a network scan cannot: physical presence. A device with no IP address, on
 * no network, still announces itself here.
 */
class BleReconModule : PentestModule {
    override val id = "t0.ble.recon"
    override val title = "Bluetooth LE reconnaissance"
    override val description =
        "Enumerates BLE devices in range — names, vendors, trackers and advertised services. " +
            "Entirely passive and needs no network. Reveals what is physically present."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.PASSIVE
    override val category = ModuleCategory.WIRELESS

    override val requiredPermissions: List<String>
        get() = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            listOf(Manifest.permission.BLUETOOTH_SCAN)
        } else {
            listOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }

    /** One device, aggregated across every advertisement heard from it. */
    private data class Device(
        val address: String,
        var name: String?,
        var companyId: Int?,
        var manufacturerData: ByteArray?,
        var services: List<String>,
        var connectable: Boolean,
        var strongest: Int,
        var sightings: Int,
    )

    @SuppressLint("MissingPermission")
    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val manager = context.androidContext
            .getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
            ?: return ModuleOutcome.Failed("No Bluetooth service on this device.")

        val adapter = manager.adapter
            ?: return ModuleOutcome.Failed("No Bluetooth adapter.")
        if (!adapter.isEnabled) {
            return ModuleOutcome.Blocked(
                "Bluetooth is switched off. It does not need to be paired or connected to anything, " +
                    "but the radio has to be on to hear advertisements.",
            )
        }

        val scanner = adapter.bluetoothLeScanner
            ?: return ModuleOutcome.Failed("BLE scanning is unavailable on this adapter.")

        val found = ConcurrentHashMap<String, Device>()

        val callback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult?) {
                val scan = result ?: return
                val address = scan.device?.address ?: return
                val record = scan.scanRecord

                val manufacturer = record?.manufacturerSpecificData
                val companyId = if (manufacturer != null && manufacturer.size() > 0) {
                    manufacturer.keyAt(0)
                } else {
                    null
                }

                found.compute(address) { _, existing ->
                    val device = existing ?: Device(
                        address = address,
                        name = null,
                        companyId = null,
                        manufacturerData = null,
                        services = emptyList(),
                        connectable = false,
                        strongest = scan.rssi,
                        sightings = 0,
                    )
                    // Advertisements are fragmentary: a name may appear in one and the
                    // manufacturer data in the next, so each field is filled as it turns up.
                    device.sightings++
                    device.strongest = maxOf(device.strongest, scan.rssi)
                    record?.deviceName?.takeIf { it.isNotBlank() }?.let { device.name = it }
                    companyId?.let { id ->
                        device.companyId = id
                        device.manufacturerData = manufacturer?.get(id)
                    }
                    record?.serviceUuids?.takeIf { it.isNotEmpty() }?.let { uuids ->
                        device.services = uuids.map { it.uuid.toString() }
                    }
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        device.connectable = device.connectable || scan.isConnectable
                    }
                    device
                }
            }
        }

        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()

        val started = runCatching { scanner.startScan(null, settings, callback) }.isSuccess
        if (!started) {
            return ModuleOutcome.Failed("Could not start the BLE scan; the permission may be missing.")
        }

        delay(SCAN_DURATION_MS)
        runCatching { scanner.stopScan(callback) }

        val devices = found.values.toList()
        if (devices.isEmpty()) {
            return ModuleOutcome.Completed("No BLE devices advertising in range.")
        }

        emitCensus(devices, emit)
        emitTrackers(devices, emit)
        emitNamedDevices(devices, emit)

        return ModuleOutcome.Completed("${devices.size} BLE device(s) in range.")
    }

    private suspend fun emitCensus(devices: List<Device>, emit: suspend (Finding) -> Unit) {
        val byVendor = devices
            .mapNotNull { it.companyId }
            .groupingBy { BleVendors.describe(it) }
            .eachCount()
        val named = devices.count { it.name != null }
        val connectable = devices.count { it.connectable }

        emit(
            Finding(
                moduleId = id,
                observedAtEpochMs = System.currentTimeMillis(),
                severity = Severity.INFO,
                title = "BLE: ${devices.size} device(s) in range",
                subject = "BLE environment",
                detail = buildString {
                    append("$named advertise a name, $connectable accept connections. ")
                    if (byVendor.isNotEmpty()) {
                        append("Vendors: ")
                        append(byVendor.entries.sortedByDescending { it.value }
                            .take(10)
                            .joinToString { "${it.value}× ${it.key}" })
                        append(".")
                    }
                },
                data = mapOf(
                    "device_count" to devices.size.toString(),
                    "named" to named.toString(),
                    "connectable" to connectable.toString(),
                    "vendors" to byVendor.entries.joinToString { "${it.key}=${it.value}" },
                ),
            ),
        )
    }

    /**
     * Trackers are worth their own finding: an item beaconing into a find-my network in a space
     * where nobody expects one is a physical surveillance question, not a connectivity one.
     */
    private suspend fun emitTrackers(devices: List<Device>, emit: suspend (Finding) -> Unit) {
        val trackers = devices.filter { device ->
            val id = device.companyId ?: return@filter false
            val data = device.manufacturerData ?: return@filter false
            BleVendors.isFindMyAdvertisement(id, data)
        }
        if (trackers.isEmpty()) return

        emit(
            Finding(
                moduleId = id,
                observedAtEpochMs = System.currentTimeMillis(),
                severity = Severity.MEDIUM,
                title = "${trackers.size} item tracker(s) advertising",
                subject = "BLE environment",
                detail = "Devices beaconing into Apple's Find My network: " +
                    trackers.joinToString { "${it.address} at ${it.strongest} dBm" } +
                    ". These are location beacons. In a space where none is expected, that is a " +
                    "physical surveillance finding rather than a network one. Addresses rotate, so " +
                    "repeat a scan to tell a stationary tracker from one passing through.",
                data = mapOf(
                    "tracker_count" to trackers.size.toString(),
                    "addresses" to trackers.joinToString { it.address },
                ),
            ),
        )
    }

    /** A device that broadcasts its name has told you what it is before you touched it. */
    private suspend fun emitNamedDevices(devices: List<Device>, emit: suspend (Finding) -> Unit) {
        devices.filter { it.name != null }.forEach { device ->
            val vendor = device.companyId?.let(BleVendors::describe)
            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    // A name that identifies a person or a specific product is information the
                    // owner almost certainly did not mean to broadcast to the street.
                    severity = if (looksPersonal(device.name!!)) Severity.LOW else Severity.INFO,
                    title = "BLE device: ${device.name}",
                    subject = device.address,
                    detail = buildString {
                        append("Advertises the name '${device.name}'. ")
                        vendor?.let { append("Manufacturer data from $it. ") }
                        append("${device.strongest} dBm, seen ${device.sightings} time(s). ")
                        append(if (device.connectable) "Accepts connections. " else "Not connectable. ")
                        if (device.services.isNotEmpty()) {
                            append("Advertises ${device.services.size} service UUID(s).")
                        }
                    },
                    data = mapOf(
                        "address" to device.address,
                        "name" to device.name.orEmpty(),
                        "vendor" to vendor.orEmpty(),
                        "rssi" to device.strongest.toString(),
                        "connectable" to device.connectable.toString(),
                        "services" to device.services.take(8).joinToString(),
                    ),
                ),
            )
        }
    }

    /** Device names routinely carry their owner's name, which is the leak worth flagging. */
    private fun looksPersonal(name: String): Boolean =
        name.contains("'") || name.split(' ', '-', '_').size > 1

    private companion object {
        const val SCAN_DURATION_MS = 12_000L
    }
}
