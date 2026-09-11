package dev.cyphernova.mobileops.core.crack

import java.io.File

/**
 * Builds the list of passphrases to try, cheapest and most likely first.
 *
 * Ordering is most of what makes an offline search useful on a handset. A phone manages a few
 * thousand PBKDF2 derivations a second, so a general-purpose wordlist of ten million entries is
 * hours of work; the same hardware finishes the patterns people actually use in seconds. The
 * ordering here is therefore deliberate rather than incidental — SSID-derived guesses, then the
 * router-label shapes, then whatever wordlist the operator supplied.
 */
object CandidateSource {

    /**
     * Passphrases derived from the network's own name.
     *
     * People name the key after the network far more often than they would admit, and these cost
     * nothing to try before anything longer starts.
     */
    fun fromSsid(ssid: String): List<String> {
        val base = ssid.trim()
        if (base.isEmpty()) return emptyList()
        val stripped = base.replace(Regex("[^A-Za-z0-9]"), "")
        val roots = listOf(base, stripped, base.lowercase(), stripped.lowercase(), stripped.uppercase())
            .filter { it.isNotBlank() }
            .distinct()

        return buildList {
            roots.forEach { root ->
                add(root)
                SUFFIXES.forEach { suffix -> add(root + suffix) }
            }
        }.filter { it.length in MIN_LENGTH..MAX_LENGTH }.distinct()
    }

    /**
     * Reads a wordlist, one passphrase per line.
     *
     * Streamed as a sequence rather than read into a list: a real wordlist is tens of megabytes
     * and pulling it into memory on a phone is how this ends as an out-of-memory crash rather
     * than a result.
     */
    fun fromFile(file: File): Sequence<String> = sequence {
        file.bufferedReader().use { reader ->
            while (true) {
                val line = reader.readLine() ?: break
                val candidate = line.trim()
                if (candidate.length in MIN_LENGTH..MAX_LENGTH) yield(candidate)
            }
        }
    }

    /** A rough count for progress reporting, without holding the file in memory. */
    fun countLines(file: File): Int = runCatching {
        file.bufferedReader().use { reader ->
            var count = 0
            while (reader.readLine() != null) count++
            count
        }
    }.getOrDefault(0)

    /**
     * The shapes that turn up on router labels and in households, which is a different
     * distribution from a leaked-password wordlist and worth trying separately.
     */
    val COMMON: List<String> = listOf(
        "password", "password1", "password123", "12345678", "123456789", "1234567890",
        "0123456789", "87654321", "qwertyuiop", "abc12345", "letmein1", "welcome1",
        "guestguest", "wifipassword", "internet", "wireless", "changeme", "administrator",
        "admin1234", "default1", "money123", "sunshine", "iloveyou", "princess1",
        "football1", "baseball1", "superman1", "trustno1", "starwars", "computer1",
    ).filter { it.length in MIN_LENGTH..MAX_LENGTH }

    private val SUFFIXES = listOf(
        "", "1", "12", "123", "1234", "12345", "123456", "2023", "2024", "2025", "2026",
        "!", "!1", "01", "00", "wifi", "Wifi", "WiFi", "password", "guest",
    )

    /** The standard admits 8 to 63 printable characters; outside that an AP would refuse it. */
    const val MIN_LENGTH = 8
    const val MAX_LENGTH = 63
}
