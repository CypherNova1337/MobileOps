package dev.cyphernova.mobileops.modules.tier0

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothClass
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleCategory
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule
import dev.cyphernova.mobileops.core.radio.BluetoothClassDecode
import kotlinx.coroutines.delay
import java.util.concurrent.ConcurrentHashMap

/**
 * Discovers classic (BR/EDR) Bluetooth devices, which BLE scanning does not see.
 *
 * The two radios share a name and nothing else. BLE advertises continuously and anyone can
 * listen; classic devices answer an inquiry only while they are discoverable — so a device that
 * shows up here has been deliberately left visible, which is itself the finding. Headsets,
 * car kits, printers, laptops and point-of-sale terminals are routinely left discoverable for
 * years after the one pairing anybody meant to do.
 *
 * Every device that answers hands over its address and its Class of Device, which says what it
 * is and what services it carries. No pairing, no connection, no network.
 */
class BluetoothClassicModule : PentestModule {
    override val id = "t0.bt.classic"
    override val title = "Bluetooth discovery (classic)"
    override val description =
        "Inquiry scan for discoverable BR/EDR devices — device class, services and signal. " +
            "Finds the laptops, printers and car kits that BLE scanning cannot see."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.ACTIVE
    override val category = ModuleCategory.RADIO

    override val requiredPermissions: List<String>
        get() = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            listOf(Manifest.permission.BLUETOOTH_SCAN)
        } else {
            listOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }

    private data class Found(
        val address: String,
        val name: String,
        val deviceClass: Int,
        val rssi: Int,
    )

    @SuppressLint("MissingPermission")
    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val androidContext = context.androidContext
        val adapter = (androidContext.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)
            ?.adapter
            ?: return ModuleOutcome.Failed("No Bluetooth adapter on this device.")

        if (!adapter.isEnabled) {
            return ModuleOutcome.Blocked(
                "Bluetooth is switched off. Nothing needs to be paired, but the radio must be on " +
                    "to run an inquiry.",
            )
        }

        val found = ConcurrentHashMap<String, Found>()
        var finished = false

        val receiver = object : BroadcastReceiver() {
            @Suppress("DEPRECATION")
            override fun onReceive(receiverContext: Context?, intent: Intent?) {
                when (intent?.action) {
                    BluetoothDevice.ACTION_FOUND -> {
                        val device: BluetoothDevice? =
                            intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)
                        val address = device?.address ?: return
                        // EXTRA_NAME rides along with the inquiry response, so the name is
                        // available without BLUETOOTH_CONNECT and without touching the device.
                        val name = intent.getStringExtra(BluetoothDevice.EXTRA_NAME).orEmpty()
                        val rssi = intent.getShortExtra(BluetoothDevice.EXTRA_RSSI, 0).toInt()
                        val deviceClass = intent
                            .getParcelableExtra<BluetoothClass>(BluetoothDevice.EXTRA_CLASS)
                            ?.let(::rawClassOf) ?: 0

                        found.compute(address) { _, existing ->
                            Found(
                                address = address,
                                name = name.ifBlank { existing?.name.orEmpty() },
                                deviceClass = if (deviceClass != 0) {
                                    deviceClass
                                } else {
                                    existing?.deviceClass ?: 0
                                },
                                rssi = maxOf(rssi, existing?.rssi ?: rssi),
                            )
                        }
                    }

                    BluetoothAdapter.ACTION_DISCOVERY_FINISHED -> finished = true
                }
            }
        }

        val filter = IntentFilter().apply {
            addAction(BluetoothDevice.ACTION_FOUND)
            addAction(BluetoothAdapter.ACTION_DISCOVERY_FINISHED)
        }

        val registered = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                androidContext.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                androidContext.registerReceiver(receiver, filter)
            }
        }
        if (registered.isFailure) {
            return ModuleOutcome.Failed("Could not register for discovery results.")
        }

        try {
            if (adapter.isDiscovering) runCatching { adapter.cancelDiscovery() }
            if (!runCatching { adapter.startDiscovery() }.getOrDefault(false)) {
                return ModuleOutcome.Failed(
                    "The inquiry could not be started; the scan permission may be missing.",
                )
            }

            // An inquiry runs about twelve seconds per round. Two rounds catches devices that
            // were mid-transmission on the first, which is common for anything doing audio.
            var waited = 0L
            while (waited < INQUIRY_BUDGET_MS) {
                delay(POLL_MS)
                waited += POLL_MS
                if (finished && waited < INQUIRY_BUDGET_MS) {
                    finished = false
                    runCatching { adapter.startDiscovery() }
                }
            }
        } finally {
            runCatching { adapter.cancelDiscovery() }
            runCatching { androidContext.unregisterReceiver(receiver) }
        }

        val devices = found.values.toList()
        if (devices.isEmpty()) {
            return ModuleOutcome.Completed(
                "No discoverable classic Bluetooth devices in range.",
            )
        }

        emitCensus(devices, emit)
        devices.sortedByDescending { it.rssi }.forEach { device -> emit(deviceFinding(device)) }

        return ModuleOutcome.Completed("${devices.size} discoverable device(s).")
    }

    /**
     * Reassembles the 24-bit Class of Device.
     *
     * [BluetoothClass] exposes no getter for the raw value: `getDeviceClass` returns only the
     * major and minor fields, and the service bits are reachable one at a time through
     * `hasService`. Putting them back together is the only supported way to recover the whole
     * field, and it is worth doing because the service bits are the half that says whether a
     * device carries data or only audio.
     */
    private fun rawClassOf(clazz: BluetoothClass): Int = runCatching {
        // getDeviceClass reports a negative sentinel rather than throwing when the field is
        // unreadable, and that value would decode into nonsense.
        var bits = clazz.deviceClass.takeIf { it > 0 } ?: 0
        SERVICE_BITS.forEach { service -> if (clazz.hasService(service)) bits = bits or service }
        bits
    }.getOrDefault(0)

    private suspend fun emitCensus(devices: List<Found>, emit: suspend (Finding) -> Unit) {
        val byClass = devices
            .groupingBy { BluetoothClassDecode.decode(it.deviceClass).major }
            .eachCount()
        val dataCapable = devices.count { BluetoothClassDecode.carriesData(it.deviceClass) }

        emit(
            Finding(
                moduleId = id,
                observedAtEpochMs = System.currentTimeMillis(),
                // Discoverable is a choice somebody made and almost never revisited. It is a
                // standing invitation to pair, and it is worth saying so once.
                severity = if (devices.isNotEmpty()) Severity.LOW else Severity.INFO,
                title = "Bluetooth: ${devices.size} discoverable device(s)",
                subject = "Bluetooth environment",
                detail = buildString {
                    append("Every device listed here is broadcasting that it will accept a ")
                    append("pairing attempt, which is a state almost nobody sets deliberately ")
                    append("and almost nobody turns off. Types: ")
                    append(byClass.entries.sortedByDescending { it.value }
                        .joinToString { "${it.value}× ${it.key}" })
                    append(". $dataCapable advertise a data-carrying service rather than audio only.")
                },
                data = mapOf(
                    "device_count" to devices.size.toString(),
                    "classes" to byClass.entries.joinToString { "${it.key}=${it.value}" },
                    "data_capable" to dataCapable.toString(),
                ),
            ),
        )
    }

    private fun deviceFinding(device: Found): Finding {
        val decoded = BluetoothClassDecode.decode(device.deviceClass)
        val dataPath = BluetoothClassDecode.carriesData(device.deviceClass)
        return Finding(
            moduleId = id,
            observedAtEpochMs = System.currentTimeMillis(),
            severity = if (dataPath) Severity.LOW else Severity.INFO,
            title = "Discoverable: ${device.name.ifBlank { decoded.label }}",
            subject = device.address,
            detail = buildString {
                if (device.name.isNotBlank()) append("Broadcasts the name '${device.name}'. ")
                append("Class of device: ${decoded.label}")
                if (decoded.services.isNotEmpty()) {
                    append(", advertising ${decoded.services.joinToString()}")
                }
                append(". ${device.rssi} dBm. ")
                if (dataPath) {
                    append(
                        "It offers a service that moves data rather than audio — networking, " +
                            "object transfer or information — which is the profile worth following up.",
                    )
                }
            },
            data = mapOf(
                "address" to device.address,
                "name" to device.name,
                "class_major" to decoded.major,
                "class_minor" to decoded.minor,
                "services" to decoded.services.joinToString(),
                "rssi" to device.rssi.toString(),
                "class_raw" to "0x%06X".format(device.deviceClass),
            ),
        )
    }

    private companion object {
        const val INQUIRY_BUDGET_MS = 24_000L
        const val POLL_MS = 1_000L

        /** Every service bit the platform names, so the raw field can be rebuilt from them. */
        val SERVICE_BITS = listOf(
            BluetoothClass.Service.LIMITED_DISCOVERABILITY,
            BluetoothClass.Service.POSITIONING,
            BluetoothClass.Service.NETWORKING,
            BluetoothClass.Service.RENDER,
            BluetoothClass.Service.CAPTURE,
            BluetoothClass.Service.OBJECT_TRANSFER,
            BluetoothClass.Service.AUDIO,
            BluetoothClass.Service.TELEPHONY,
            BluetoothClass.Service.INFORMATION,
        )
    }
}
