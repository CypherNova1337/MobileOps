package dev.cyphernova.mobileops.core.tls

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** One request seen in the clear inside an intercepted flow. */
data class InterceptedRequest(
    val host: String,
    val method: String,
    val path: String,
    val secrets: List<SecretExposure>,
    val observedAtEpochMs: Long = System.currentTimeMillis(),
) {
    val url: String get() = "https://$host$path"
}

/**
 * Shared state for TLS interception: whether it is armed, what it has seen, and how it is doing.
 *
 * The capture service is the producer and the UI is the consumer; both live in the same process,
 * so this is the meeting point rather than a bound service.
 */
object InterceptController {

    private val _enabled = MutableStateFlow(false)
    val enabled: StateFlow<Boolean> = _enabled.asStateFlow()

    private val _requests = MutableStateFlow<List<InterceptedRequest>>(emptyList())
    val requests: StateFlow<List<InterceptedRequest>> = _requests.asStateFlow()

    private val _counters = MutableStateFlow<Map<String, Long>>(emptyMap())
    val counters: StateFlow<Map<String, Long>> = _counters.asStateFlow()

    private val _caFingerprint = MutableStateFlow<String?>(null)
    val caFingerprint: StateFlow<String?> = _caFingerprint.asStateFlow()

    val isEnabled: Boolean get() = _enabled.value

    fun setEnabled(enabled: Boolean) {
        _enabled.value = enabled
    }

    internal fun record(host: String, exchange: HttpExchange) {
        val request = InterceptedRequest(
            host = exchange.host ?: host,
            method = exchange.method,
            path = exchange.path,
            secrets = exchange.secrets,
        )
        // Bounded: a browsing session generates thousands, and the evidence log is the durable
        // record — this list only backs the live view.
        _requests.value = (_requests.value + request).takeLast(MAX_RETAINED)
    }

    internal fun publish(counters: Map<String, Long>) {
        _counters.value = counters
    }

    internal fun setFingerprint(fingerprint: String?) {
        _caFingerprint.value = fingerprint
    }

    fun clearRequests() {
        _requests.value = emptyList()
    }

    private const val MAX_RETAINED = 500
}
