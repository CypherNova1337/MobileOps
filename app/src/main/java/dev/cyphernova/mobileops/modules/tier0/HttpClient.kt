package dev.cyphernova.mobileops.modules.tier0

import dev.cyphernova.mobileops.core.exploit.HttpResponse
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSession
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * A deliberately small HTTP client for probing devices on the local network.
 *
 * Certificate validation is disabled **only here**, and only because the targets are LAN
 * appliances that ship self-signed certificates — refusing them would mean auditing nothing on
 * the devices most likely to be misconfigured. This client never talks to anything but a target
 * the operator selected, and it is entirely separate from the interception path, where the
 * upstream leg validates properly.
 */
object LanHttpClient {

    suspend fun probe(
        url: String,
        method: String = "GET",
        authorization: String? = null,
        followRedirects: Boolean = false,
        timeoutMs: Int = 5_000,
        body: ByteArray? = null,
        headers: Map<String, String> = emptyMap(),
    ): HttpResponse? = withContext(Dispatchers.IO) {
        val started = System.currentTimeMillis()
        runCatching {
            val connection = (URL(url).openConnection() as HttpURLConnection).apply {
                requestMethod = method
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                instanceFollowRedirects = followRedirects
                setRequestProperty("User-Agent", USER_AGENT)
                setRequestProperty("Accept", "*/*")
                authorization?.let { setRequestProperty("Authorization", it) }
                headers.forEach { (name, value) -> setRequestProperty(name, value) }

                if (body != null) {
                    doOutput = true
                    setFixedLengthStreamingMode(body.size)
                }

                if (this is HttpsURLConnection) {
                    sslSocketFactory = permissiveContext.socketFactory
                    setHostnameVerifier { _: String, _: SSLSession -> true }
                }
            }

            body?.let { payload ->
                connection.outputStream.use { it.write(payload) }
            }

            val status = connection.responseCode
            val responseHeaders = connection.headerFields
                .filterKeys { it != null }
                .map { (key, values) -> key.lowercase() to values.joinToString(", ") }
                .toMap()

            val stream = if (status in 200..399) connection.inputStream else connection.errorStream
            val responseBody = stream?.use { input ->
                // Bounded: a probe should not pull a firmware image into memory.
                val buffer = ByteArray(MAX_BODY_BYTES)
                var total = 0
                while (total < MAX_BODY_BYTES) {
                    val read = input.read(buffer, total, MAX_BODY_BYTES - total)
                    if (read <= 0) break
                    total += read
                }
                String(buffer, 0, total, Charsets.ISO_8859_1)
            }.orEmpty()

            connection.disconnect()
            HttpResponse(status, responseHeaders, responseBody, System.currentTimeMillis() - started)
        }.getOrNull()
    }

    /**
     * Accepts any certificate. Scoped to this object and used only against operator-selected LAN
     * hosts; see the class comment for why that trade is the right one here and nowhere else.
     */
    private val permissiveContext: SSLContext by lazy {
        val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) = Unit
            override fun checkServerTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) = Unit
            override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
        }
        SSLContext.getInstance("TLS").apply {
            init(null, arrayOf<TrustManager>(trustAll), java.security.SecureRandom())
        }
    }

    private const val MAX_BODY_BYTES = 64 * 1024
    private const val USER_AGENT = "Mozilla/5.0 (Linux; Android) MobileOps"
}
