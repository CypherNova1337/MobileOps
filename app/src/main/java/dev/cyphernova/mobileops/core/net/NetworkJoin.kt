package dev.cyphernova.mobileops.core.net

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.WifiNetworkSpecifier
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Where the app's own WiFi association stands. */
data class JoinStatus(
    val ssid: String? = null,
    val joined: Boolean = false,
    val bound: Boolean = false,
    val detail: String = "",
)

/**
 * Joins a WiFi network from inside the app, without changing the phone's own connection.
 *
 * `WifiNetworkSpecifier` gets a per-app association: the user approves once in a system dialog,
 * and the app receives a [Network] that is not the device default. Binding the process to it
 * points every socket this app opens at that network, which is what lets the LAN modules run
 * against a target the handset has not otherwise joined — useful when the phone must stay on
 * cellular, or when testing a guest network without leaving the operator's own connection.
 *
 * The association ends when the request is released or the app exits, so nothing is left behind
 * on the device.
 */
class NetworkJoin(private val context: Context) {

    private val connectivity =
        context.applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    private var callback: ConnectivityManager.NetworkCallback? = null

    companion object {
        private val _status = MutableStateFlow(JoinStatus())
        val status: StateFlow<JoinStatus> = _status.asStateFlow()

        /** Passphrase for the next join, set from the UI and never written to the evidence log. */
        @Volatile
        var passphrase: String = ""

        val isJoined: Boolean get() = _status.value.joined
    }

    val supported: Boolean get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q

    /**
     * Requests the association and waits for it to come up.
     *
     * @return null on success, or the reason it failed.
     */
    suspend fun join(ssid: String, timeoutMs: Long = 30_000): String? {
        if (!supported) return "Per-app WiFi association needs Android 10 or later."
        release()

        val specifier = WifiNetworkSpecifier.Builder()
            .setSsid(ssid)
            .apply {
                // An empty passphrase means an open network; supplying one selects WPA2/WPA3.
                if (passphrase.isNotBlank()) setWpa2Passphrase(passphrase)
            }
            .build()

        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            // Deliberately omits NET_CAPABILITY_INTERNET: a network under test may well have no
            // working upstream, and demanding internet would reject exactly those.
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .setNetworkSpecifier(specifier)
            .build()

        var result: String? = "Timed out waiting for the association."
        val latch = java.util.concurrent.CountDownLatch(1)

        val networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                // Binding the process is what makes this useful: without it the app would hold a
                // network it never sends anything over.
                val bound = runCatching { connectivity.bindProcessToNetwork(network) }
                    .getOrDefault(false)
                _status.value = JoinStatus(
                    ssid = ssid,
                    joined = true,
                    bound = bound,
                    detail = if (bound) {
                        "Joined and bound; this app's traffic now uses $ssid."
                    } else {
                        "Joined, but the process could not be bound to it."
                    },
                )
                result = null
                latch.countDown()
            }

            override fun onUnavailable() {
                _status.value = JoinStatus(ssid = ssid, detail = "The request was refused or cancelled.")
                result = "The association was refused, or the dialog was dismissed."
                latch.countDown()
            }

            override fun onLost(network: Network) {
                runCatching { connectivity.bindProcessToNetwork(null) }
                _status.value = JoinStatus(ssid = ssid, detail = "The association dropped.")
            }
        }

        callback = networkCallback
        val requested = runCatching {
            // The request carries the specifier; without it the system has nothing to prompt about.
            connectivity.requestNetwork(request, networkCallback, timeoutMs.toInt())
        }
        if (requested.isFailure) {
            return "Could not raise the association request: " +
                (requested.exceptionOrNull()?.message ?: "unknown error")
        }

        // The latch blocks until the system dialog is answered, which can be half a minute.
        // Modules run on the caller's dispatcher, so waiting here without moving off it would
        // freeze the UI for the duration.
        withContext(Dispatchers.IO) {
            runCatching { latch.await(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS) }
        }
        return result
    }

    /** Drops the association and unbinds, restoring the device's normal routing for this app. */
    fun release() {
        runCatching { connectivity.bindProcessToNetwork(null) }
        callback?.let { runCatching { connectivity.unregisterNetworkCallback(it) } }
        callback = null
        _status.value = JoinStatus()
    }
}
