package dev.cyphernova.mobileops.core.capability

import android.content.Context
import android.hardware.usb.UsbManager

/** A USB WiFi adapter recognised by its vendor and product id. */
data class UsbWifiAdapter(
    val vendorId: Int,
    val productId: Int,
    val chipset: String,
    val driver: String,
    /** Firmware the driver loads from /lib/firmware, where the chipset needs one. */
    val firmware: String?,
    val monitorCapable: Boolean,
    val injectionCapable: Boolean,
    val productName: String?,
    /** True when a kernel interface appeared for it — the difference between plugged in and usable. */
    val claimedByKernel: Boolean,
) {
    val identifier: String get() = "%04x:%04x".format(vendorId, productId)

    /** What is standing between this adapter and monitor mode, in the order it has to be fixed. */
    fun blockers(rooted: Boolean): List<String> = buildList {
        if (!claimedByKernel) {
            add(
                "No kernel interface appeared, so no driver has claimed it. Stock Android kernels " +
                    "do not ship $driver; it has to be built into the kernel or loaded as a module.",
            )
            firmware?.let {
                add("$driver also loads firmware '$it', which must be present under /lib/firmware.")
            }
        }
        if (!rooted) {
            add("Root is required to load a module, place firmware, or reconfigure an interface.")
        }
        if (!monitorCapable) {
            add("This chipset does not support monitor mode even with a working driver.")
        }
    }
}

/**
 * Looks for known WiFi adapters on the USB bus.
 *
 * Enumeration needs no permission — only opening a device does — so this can report an adapter
 * the kernel has ignored. That distinction is the useful one: an adapter that enumerates but
 * gets no interface looks identical to a broken adapter from `/sys/class/net` alone, and the
 * fix for each is entirely different.
 */
class UsbWifiProbe(private val context: Context) {

    fun detect(claimedInterfaces: List<String>): List<UsbWifiAdapter> {
        val manager = context.getSystemService(Context.USB_SERVICE) as? UsbManager
            ?: return emptyList()

        val devices = runCatching { manager.deviceList.values.toList() }.getOrDefault(emptyList())

        // A second wlan interface is the signal that something beyond the internal radio was
        // claimed. It cannot be tied to a specific device without the kernel's USB tree, which
        // is not readable here, so this is attributed to the one adapter when there is one.
        val extraInterfaces = claimedInterfaces.filter { it != "wlan0" }

        return devices.mapNotNull { device ->
            val known = KNOWN[device.vendorId to device.productId] ?: return@mapNotNull null
            UsbWifiAdapter(
                vendorId = device.vendorId,
                productId = device.productId,
                chipset = known.chipset,
                driver = known.driver,
                firmware = known.firmware,
                monitorCapable = known.monitorCapable,
                injectionCapable = known.injectionCapable,
                productName = runCatching { device.productName }.getOrNull(),
                claimedByKernel = extraInterfaces.isNotEmpty(),
            )
        }
    }

    private data class KnownAdapter(
        val chipset: String,
        val driver: String,
        val firmware: String?,
        val monitorCapable: Boolean,
        val injectionCapable: Boolean,
    )

    private companion object {
        /**
         * The adapters people actually buy for this work. Not exhaustive — an unlisted adapter
         * is reported as unknown rather than guessed at, because claiming injection support that
         * does not exist would waste an engagement.
         */
        val KNOWN: Map<Pair<Int, Int>, KnownAdapter> = mapOf(
            // Atheros AR9271 — Alfa AWUS036NHA, TP-Link TL-WN722N v1. The reference adapter.
            (0x0cf3 to 0x9271) to KnownAdapter("Atheros AR9271", "ath9k_htc", "htc_9271.fw", true, true),
            (0x0cf3 to 0x1006) to KnownAdapter("Atheros AR9271", "ath9k_htc", "htc_9271.fw", true, true),
            (0x0cf3 to 0x7015) to KnownAdapter("Atheros AR7010", "ath9k_htc", "htc_7010.fw", true, true),
            // Realtek RTL8187 — Alfa AWUS036H, the older classic.
            (0x0bda to 0x8187) to KnownAdapter("Realtek RTL8187", "rtl8187", null, true, true),
            (0x0846 to 0x6100) to KnownAdapter("Realtek RTL8187", "rtl8187", null, true, true),
            // Realtek RTL8812AU — Alfa AWUS036ACH, dual band, out-of-tree driver.
            (0x0bda to 0x8812) to KnownAdapter("Realtek RTL8812AU", "88XXau (out of tree)", null, true, true),
            (0x2357 to 0x0101) to KnownAdapter("Realtek RTL8812AU", "88XXau (out of tree)", null, true, true),
            (0x0bda to 0x881a) to KnownAdapter("Realtek RTL8812AU", "88XXau (out of tree)", null, true, true),
            (0x0bda to 0xc811) to KnownAdapter("Realtek RTL8811CU", "8821cu (out of tree)", null, true, true),
            // Ralink/MediaTek.
            (0x148f to 0x5370) to KnownAdapter("Ralink RT5370", "rt2800usb", null, true, true),
            (0x148f to 0x3070) to KnownAdapter("Ralink RT3070", "rt2800usb", null, true, true),
            (0x0e8d to 0x7612) to KnownAdapter("MediaTek MT7612U", "mt76x2u", null, true, true),
            (0x0e8d to 0x7610) to KnownAdapter("MediaTek MT7610U", "mt76x0u", null, true, true),
        )
    }
}
