package dev.cyphernova.mobileops.modules.tier0

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkAddress
import dev.cyphernova.mobileops.core.net.Cidr4
import java.net.Inet4Address

/** Where this device sits on the network, as the platform reports it. */
data class NetworkPosition(
    val localAddress: String,
    val prefixLength: Int,
    val gateway: String?,
    val dnsServers: List<String>,
    val interfaceName: String?,
) {
    /** The CIDR block this device is attached to, e.g. `192.168.1.0/24`. */
    val cidr: String
        get() {
            val value = Cidr4.parseAddress(localAddress) ?: return "$localAddress/$prefixLength"
            val mask = if (prefixLength == 0) 0L else (0xFFFFFFFFL shl (32 - prefixLength)) and 0xFFFFFFFFL
            val network = value and mask
            return "${Cidr4.toDotted(network)}/$prefixLength"
        }
}

/**
 * Resolves the device's IPv4 position from [ConnectivityManager]. This is the supported route
 * on a stock device — reading `/proc/net` directly has been blocked for apps by SELinux since
 * Android 10.
 */
object LocalNetwork {

    fun position(context: Context): NetworkPosition? {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return null
        val network = manager.activeNetwork ?: return null
        val properties = manager.getLinkProperties(network) ?: return null

        val v4: LinkAddress = properties.linkAddresses
            .firstOrNull { it.address is Inet4Address && !it.address.isLoopbackAddress }
            ?: return null

        val gateway = properties.routes
            .firstOrNull { it.isDefaultRoute && it.gateway is Inet4Address }
            ?.gateway?.hostAddress

        return NetworkPosition(
            localAddress = v4.address.hostAddress.orEmpty(),
            prefixLength = v4.prefixLength,
            gateway = gateway,
            dnsServers = properties.dnsServers.mapNotNull { it.hostAddress },
            interfaceName = properties.interfaceName,
        )
    }
}
