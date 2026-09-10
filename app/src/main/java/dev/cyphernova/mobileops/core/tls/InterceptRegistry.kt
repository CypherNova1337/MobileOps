package dev.cyphernova.mobileops.core.tls

import java.util.concurrent.ConcurrentHashMap

/** Where a flow was really headed, before it was diverted to the local interceptor. */
data class OriginalDestination(val ip: String, val port: Int)

/**
 * Carries the true destination across the hop through loopback.
 *
 * The relay diverts an intercepted flow to a local listener, which loses the destination the
 * client asked for. The relay binds its socket first, so the local port is known before the
 * connection exists, and that port is the key the listener looks the destination up by — no
 * race, because registration happens strictly before connect.
 */
object InterceptRegistry {

    private val byLocalPort = ConcurrentHashMap<Int, OriginalDestination>()

    fun register(localPort: Int, destination: OriginalDestination) {
        byLocalPort[localPort] = destination
    }

    fun claim(localPort: Int): OriginalDestination? = byLocalPort.remove(localPort)

    fun clear() = byLocalPort.clear()

    val pending: Int get() = byLocalPort.size
}
