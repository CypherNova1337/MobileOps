package dev.cyphernova.mobileops.core.tls

/** What the plaintext inside an intercepted flow turned out to be. */
data class HttpExchange(
    val method: String,
    val path: String,
    val version: String,
    val headers: Map<String, String>,
    val secrets: List<SecretExposure>,
) {
    val host: String? get() = headers["host"]
    val url: String get() = host?.let { "https://$it$path" } ?: path
}

/** Something in the request that would matter if the channel were not trusted. */
data class SecretExposure(val kind: String, val where: String, val detail: String)

/**
 * Reads the request line and headers out of decrypted traffic.
 *
 * The point of interception is seeing what an app actually sends, so this looks specifically for
 * the things that show up in findings: bearer tokens, API keys, session cookies, basic auth.
 * Values are described, never logged in full — an evidence file that contains live credentials
 * is its own problem.
 */
object HttpPeek {

    private val METHODS = setOf(
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT",
    )

    private val SECRET_QUERY_KEYS = listOf(
        "api_key", "apikey", "access_token", "token", "auth", "key", "password", "passwd",
        "secret", "session", "sig", "signature",
    )

    fun parse(data: ByteArray, length: Int = data.size): HttpExchange? {
        val text = String(data, 0, minOf(length, MAX_PEEK), Charsets.ISO_8859_1)
        val headerBlock = text.substringBefore("\r\n\r\n")
        val lines = headerBlock.split("\r\n").filter { it.isNotBlank() }
        if (lines.isEmpty()) return null

        val requestLine = lines.first().split(' ')
        if (requestLine.size < 3) return null
        val method = requestLine[0]
        if (method !in METHODS) return null

        val path = requestLine[1]
        val version = requestLine[2]

        val headers = lines.drop(1).mapNotNull { line ->
            val name = line.substringBefore(':', "").trim().lowercase()
            val value = line.substringAfter(':', "").trim()
            if (name.isBlank() || value.isBlank()) null else name to value
        }.toMap()

        return HttpExchange(
            method = method,
            path = path,
            version = version,
            headers = headers,
            secrets = findSecrets(path, headers),
        )
    }

    private fun findSecrets(path: String, headers: Map<String, String>): List<SecretExposure> =
        buildList {
            headers["authorization"]?.let { value ->
                val scheme = value.substringBefore(' ').ifBlank { "unknown" }
                add(
                    SecretExposure(
                        kind = "Authorization header",
                        where = "header",
                        detail = "$scheme credential, ${value.length} chars" +
                            if (scheme.equals("Basic", ignoreCase = true)) {
                                " — Basic is base64, not encryption"
                            } else {
                                ""
                            },
                    ),
                )
            }

            headers["cookie"]?.let { value ->
                val names = value.split(';').mapNotNull {
                    it.substringBefore('=').trim().takeIf(String::isNotBlank)
                }
                add(
                    SecretExposure(
                        kind = "Cookie",
                        where = "header",
                        detail = "${names.size} cookie(s): ${names.take(8).joinToString()}",
                    ),
                )
            }

            headers.keys.filter { it.startsWith("x-api") || it.endsWith("-token") || it.endsWith("-key") }
                .forEach { name ->
                    add(SecretExposure("Credential header", "header", "$name is present"))
                }

            val query = path.substringAfter('?', "")
            if (query.isNotBlank()) {
                query.split('&').forEach { pair ->
                    val key = pair.substringBefore('=').lowercase()
                    if (SECRET_QUERY_KEYS.any { key == it || key.endsWith("_$it") }) {
                        add(
                            SecretExposure(
                                kind = "Credential in URL",
                                where = "query string",
                                detail = "'$key' is passed in the query string, where it lands in " +
                                    "server logs, proxy logs and Referer headers",
                            ),
                        )
                    }
                }
            }
        }

    private const val MAX_PEEK = 8 * 1024
}
