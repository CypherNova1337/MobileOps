package dev.cyphernova.mobileops.modules.tier0

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkAddress
import android.net.NetworkCapabilities
import dev.cyphernova.mobileops.core.net.Cidr4
import java.net.Inet4Address

/** How this device is attached, which decides whether LAN modules have anything to work with. */
enum class Transport(val label: String) {
    WIFI("WiFi"),
    CELLULAR("cellular"),
    ETHERNET("Ethernet"),
    VPN("VPN"),
    OTHER("unknown link"),
}

/** Where this device sits on the network, as the platform reports it. */
data class NetworkPosition(
    val localAddress: String,
    val prefixLength: Int,
    val gateway: String?,
    val dnsServers: List<String>,
    val interfaceName: String?,
    val transport: Transport,
) {
    /**
     * A /31 or /32 is a point-to-point link with no neighbours — which is exactly what a mobile
     * carrier hands out. There is no subnet to sweep, and saying "254 addresses to probe" on one
     * would be inventing a network that does not exist.
     */
    val isPointToPoint: Boolean get() = prefixLength >= 31

    val hasLocalSubnet: Boolean get() = !isPointToPoint && transport != Transport.CELLULAR

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

        val capabilities = manager.getNetworkCapabilities(network)
        val transport = when {
            capabilities == null -> Transport.OTHER
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> Transport.WIFI
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> Transport.CELLULAR
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> Transport.ETHERNET
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> Transport.VPN
            else -> Transport.OTHER
        }

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
            transport = transport,
        )
    }
}
