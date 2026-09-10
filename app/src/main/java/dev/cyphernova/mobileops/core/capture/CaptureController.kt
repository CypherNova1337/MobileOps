package dev.cyphernova.mobileops.core.capture

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Live state of the capture, published by the service and read by the UI and the module. */
data class CaptureStatus(
    val running: Boolean = false,
    val packets: Long = 0,
    val bytes: Long = 0,
    val tcpFlows: Int = 0,
    val udpFlows: Int = 0,
    val pcapPath: String? = null,
    val startedAtEpochMs: Long = 0,
    val error: String? = null,
    val counters: Map<String, Long> = emptyMap(),
    val diagnosis: String = "",
)

/**
 * Shared handle on the capture service. A bound service connection would be the textbook answer,
 * but the service and the UI live in the same process and this keeps the state readable from
 * both without ceremony.
 */
object CaptureController {

    private val _status = MutableStateFlow(CaptureStatus())
    val status: StateFlow<CaptureStatus> = _status.asStateFlow()

    val isRunning: Boolean get() = _status.value.running

    internal fun started(pcapPath: String) {
        _status.value = CaptureStatus(
            running = true,
            pcapPath = pcapPath,
            startedAtEpochMs = System.currentTimeMillis(),
        )
    }

    internal fun update(
        packets: Long,
        bytes: Long,
        tcpFlows: Int,
        udpFlows: Int,
        stats: CaptureStats,
    ) {
        _status.value = _status.value.copy(
            packets = packets,
            bytes = bytes,
            tcpFlows = tcpFlows,
            udpFlows = udpFlows,
            counters = stats.snapshot(),
            diagnosis = stats.diagnose(),
        )
    }

    internal fun stopped(error: String? = null) {
        _status.value = _status.value.copy(
            running = false,
            tcpFlows = 0,
            udpFlows = 0,
            error = error,
        )
    }
}
