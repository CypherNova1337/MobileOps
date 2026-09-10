package dev.cyphernova.mobileops.core.target

/** Something the operator has picked to point a module at. */
sealed interface Target {
    /** Stable identity used for selection state — two targets with the same key are the same thing. */
    val key: String
    val label: String

    /** A WiFi network seen in a scan. */
    data class Network(
        val ssid: String,
        val bssid: String,
        val frequencyMhz: Int,
        val capabilities: String,
        val rssiDbm: Int,
    ) : Target {
        override val key = "net:$bssid"
        override val label = ssid.ifBlank { "<hidden>" }
    }

    /** A host on the network, either discovered by a sweep or typed in. */
    data class Host(val address: String, val hostname: String? = null) : Target {
        override val key = "host:$address"
        override val label = hostname?.takeIf { it.isNotBlank() }?.let { "$address ($it)" } ?: address
    }

    /** A specific service on a host. */
    data class Endpoint(val host: String, val port: Int) : Target {
        override val key = "ep:$host:$port"
        override val label = "$host:$port"
    }
}

/** The current selection, handed to modules so they know what to point at. */
data class TargetSelection(val targets: List<Target> = emptyList()) {

    val isEmpty: Boolean get() = targets.isEmpty()

    /** Every selected target flattened to a bare host address. */
    fun hosts(): List<String> = targets.mapNotNull { target ->
        when (target) {
            is Target.Host -> target.address
            is Target.Endpoint -> target.host
            is Target.Network -> null
        }
    }.distinct()

    /** Selected targets as host/port pairs, filling in [defaultPort] for bare hosts. */
    fun endpoints(defaultPort: Int): List<Pair<String, Int>> = targets.mapNotNull { target ->
        when (target) {
            is Target.Endpoint -> target.host to target.port
            is Target.Host -> target.address to defaultPort
            is Target.Network -> null
        }
    }.distinct()

    fun networks(): List<Target.Network> = targets.filterIsInstance<Target.Network>()
}
