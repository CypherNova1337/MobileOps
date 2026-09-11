package dev.cyphernova.mobileops.modules.tier0

import android.content.Context
import android.net.wifi.WifiManager
import dev.cyphernova.mobileops.core.capability.Tier
import dev.cyphernova.mobileops.core.discovery.Mdns
import dev.cyphernova.mobileops.core.discovery.Nbns
import dev.cyphernova.mobileops.core.discovery.Ssdp
import dev.cyphernova.mobileops.core.evidence.Finding
import dev.cyphernova.mobileops.core.evidence.Severity
import dev.cyphernova.mobileops.core.module.Intrusiveness
import dev.cyphernova.mobileops.core.module.ModuleContext
import dev.cyphernova.mobileops.core.module.ModuleOutcome
import dev.cyphernova.mobileops.core.module.PentestModule
import dev.cyphernova.mobileops.core.net.Cidr4
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.MulticastSocket

/**
 * Asks the network what it is running, using the protocols devices already answer.
 *
 * Reverse DNS is empty on most networks, so a sweep reports bare addresses. These three
 * protocols are how devices actually announce themselves — NetBIOS for Windows and SMB, mDNS for
 * Apple, Android and printers, SSDP for consumer routers and media gear — and all three work
 * from an unprivileged socket.
 */
class ServiceDiscoveryModule : PentestModule {
    override val id = "t0.net.services"
    override val title = "Service & name discovery"
    override val description =
        "Resolves host names and running services via NetBIOS, mDNS and SSDP — the announcements " +
            "devices already make. Fills in the names reverse DNS cannot."
    override val requiredTier = Tier.T0_STOCK
    override val intrusiveness = Intrusiveness.ACTIVE

    override suspend fun run(
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): ModuleOutcome {
        val position = LocalNetwork.position(context.androidContext)
            ?: return ModuleOutcome.Failed("No active IPv4 network.")

        if (!position.hasLocalSubnet && context.targets.hosts().isEmpty()) {
            return ModuleOutcome.Blocked(
                "This device is on ${position.transport.label} with no local subnet. Multicast " +
                    "discovery has nowhere to go and there are no neighbours to query.",
            )
        }

        // Multicast is filtered out by the WiFi stack for power reasons unless a lock is held,
        // so mDNS and SSDP replies would silently never arrive without this.
        val wifi = context.androidContext.applicationContext
            .getSystemService(Context.WIFI_SERVICE) as? WifiManager
        val lock = wifi?.createMulticastLock("mobileops-discovery")?.apply {
            setReferenceCounted(false)
            runCatching { acquire() }
        }

        var found = 0
        try {
            found += discoverNetbios(position, context, emit)
            found += discoverMdns(emit)
            found += discoverSsdp(emit)
        } finally {
            runCatching { lock?.release() }
        }

        return ModuleOutcome.Completed("$found announcement(s) collected.")
    }

    /** Asks each host on the subnet directly for the names it claims. */
    private suspend fun discoverNetbios(
        position: NetworkPosition,
        context: ModuleContext,
        emit: suspend (Finding) -> Unit,
    ): Int {
        val selected = context.targets.hosts()
        val candidates = selected.ifEmpty {
            if (position.prefixLength < MIN_PREFIX) emptyList() else Cidr4.hosts(position.cidr, MAX_HOSTS)
        }
        if (candidates.isEmpty()) return 0

        val results = coroutineScope {
            candidates.chunked(CONCURRENCY).flatMap { batch ->
                batch.map { address -> async(Dispatchers.IO) { address to queryNetbios(address) } }.awaitAll()
            }
        }

        var count = 0
        results.forEach { (address, names) ->
            if (names.isEmpty()) return@forEach
            count++

            val workstation = names.firstOrNull { it.isWorkstation }?.name
            val workgroup = names.firstOrNull { it.isDomainOrWorkgroup }?.name
            val fileServer = names.any { it.isFileServer }

            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    severity = Severity.INFO,
                    title = "NetBIOS name: ${workstation ?: address}",
                    subject = address,
                    detail = buildString {
                        workstation?.let { append("Host name '$it'. ") }
                        workgroup?.let { append("Workgroup or domain '$it'. ") }
                        if (fileServer) append("Advertises the file-server service. ")
                        append("Claims ${names.size} name(s): ${names.joinToString { it.name }}.")
                    },
                    data = mapOf(
                        "hostname" to workstation.orEmpty(),
                        "workgroup" to workgroup.orEmpty(),
                        "file_server" to fileServer.toString(),
                        "names" to names.joinToString { "${it.name}<%02X>".format(it.suffix) },
                    ),
                ),
            )
        }
        return count
    }

    private fun queryNetbios(address: String): List<Nbns.NetbiosName> = runCatching {
        DatagramSocket().use { socket ->
            socket.soTimeout = UNICAST_TIMEOUT_MS
            val request = Nbns.nodeStatusRequest()
            socket.send(DatagramPacket(request, request.size, InetAddress.getByName(address), Nbns.PORT))

            val buffer = ByteArray(BUFFER_BYTES)
            val response = DatagramPacket(buffer, buffer.size)
            socket.receive(response)
            Nbns.parseNodeStatusResponse(buffer, response.length)
        }
    }.getOrDefault(emptyList())

    /** Enumerates service types, then asks who provides each one. */
    private suspend fun discoverMdns(emit: suspend (Finding) -> Unit): Int = withContext(Dispatchers.IO) {
        val replies = multicastExchange(
            group = Mdns.GROUP,
            port = Mdns.PORT,
            payload = Mdns.query(Mdns.SERVICE_ENUMERATION),
        )

        val records = replies.flatMap { (source, data) ->
            Mdns.parseResponse(data, data.size).map { source to it }
        }
        if (records.isEmpty()) return@withContext 0

        val byHost = records.groupBy { it.first }
        byHost.forEach { (source, entries) ->
            val services = entries.mapNotNull { it.second.target }.distinct()
            if (services.isEmpty()) return@forEach

            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    severity = Severity.INFO,
                    title = "mDNS: $source advertises ${services.size} service(s)",
                    subject = source,
                    detail = "Announced over multicast DNS: ${services.take(12).joinToString()}" +
                        if (services.size > 12) ", and ${services.size - 12} more." else ".",
                    data = mapOf("services" to services.joinToString()),
                ),
            )
        }
        byHost.size
    }

    private suspend fun discoverSsdp(emit: suspend (Finding) -> Unit): Int = withContext(Dispatchers.IO) {
        val replies = multicastExchange(
            group = Ssdp.GROUP,
            port = Ssdp.PORT,
            payload = Ssdp.mSearch(),
        )

        val byHost = replies.mapNotNull { (source, data) ->
            Ssdp.parseReply(data, data.size)?.let { source to it }
        }.groupBy({ it.first }, { it.second })

        byHost.forEach { (source, entries) ->
            val server = entries.firstNotNullOfOrNull { it.server }
            val location = entries.firstNotNullOfOrNull { it.location }
            val targets = entries.mapNotNull { it.searchTarget }.distinct()

            emit(
                Finding(
                    moduleId = id,
                    observedAtEpochMs = System.currentTimeMillis(),
                    // A Server header names the product and often its firmware version, which is
                    // the fastest route from "a device is here" to "this device has known CVEs".
                    severity = if (server != null) Severity.LOW else Severity.INFO,
                    title = "UPnP: ${server ?: source}",
                    subject = source,
                    detail = buildString {
                        server?.let { append("Identifies itself as '$it'. ") }
                        location?.let { append("Device description at $it. ") }
                        if (targets.isNotEmpty()) append("Offers ${targets.size} service type(s).")
                    },
                    data = mapOf(
                        "server" to server.orEmpty(),
                        "location" to location.orEmpty(),
                        "service_types" to targets.take(20).joinToString(),
                    ),
                ),
            )
        }
        byHost.size
    }

    /** Sends one multicast probe and collects every reply until the window closes. */
    private fun multicastExchange(
        group: String,
        port: Int,
        payload: ByteArray,
    ): List<Pair<String, ByteArray>> = runCatching {
        MulticastSocket().use { socket ->
            socket.soTimeout = MULTICAST_POLL_MS
            socket.reuseAddress = true
            val address = InetAddress.getByName(group)
            socket.send(DatagramPacket(payload, payload.size, InetSocketAddress(address, port)))

            val replies = mutableListOf<Pair<String, ByteArray>>()
            val deadline = System.currentTimeMillis() + MULTICAST_WINDOW_MS
            while (System.currentTimeMillis() < deadline && replies.size < MAX_REPLIES) {
                val buffer = ByteArray(BUFFER_BYTES)
                val packet = DatagramPacket(buffer, buffer.size)
                val received = runCatching { socket.receive(packet); true }.getOrDefault(false)
                if (!received) continue
                replies += (packet.address?.hostAddress ?: "unknown") to buffer.copyOf(packet.length)
            }
            replies
        }
    }.getOrDefault(emptyList())

    private companion object {
        const val MIN_PREFIX = 22
        const val MAX_HOSTS = 254
        const val CONCURRENCY = 32
        const val UNICAST_TIMEOUT_MS = 500
        const val MULTICAST_POLL_MS = 700
        const val MULTICAST_WINDOW_MS = 4_000L
        const val MAX_REPLIES = 200
        const val BUFFER_BYTES = 4096
    }
}
