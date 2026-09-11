package dev.cyphernova.mobileops.core.crack

/**
 * Tests candidate passphrases against a captured handshake.
 *
 * This is the whole offline attack on WPA2-PSK, and its shape is worth being precise about:
 * there is no weakness in the protocol being exploited here. The handshake is exactly as strong
 * as the passphrase behind it. What the capture removes is the *network* — no AP to rate-limit
 * guesses, no lockout, no log entry, no way for anyone to know the search is happening. A
 * passphrase that would survive forever online falls in minutes offline if it is weak.
 *
 * Which is why the honest result of a failed run is "this passphrase is not in this list", never
 * "this network is secure".
 */
object PassphraseSearch {

    data class Progress(val tried: Int, val total: Int, val candidate: String)

    sealed interface Result {
        data class Found(val passphrase: String, val tried: Int) : Result
        data class Exhausted(val tried: Int) : Result
        data class Stopped(val tried: Int, val reason: String) : Result
    }

    /**
     * Walks the candidates against every capture for one SSID.
     *
     * The PMK derivation is the expensive step — 4096 rounds of HMAC-SHA1 — and it depends only
     * on the passphrase and the SSID, so it happens once per candidate and is then checked
     * against each capture. Grouping by SSID before calling this is what makes that saving real.
     *
     * @param onProgress called periodically so a long run can be reported rather than looking hung.
     * @param shouldContinue polled between candidates, so a run can be given a deadline.
     */
    suspend fun search(
        ssid: String,
        captures: List<HandshakeCapture>,
        candidates: Sequence<String>,
        total: Int,
        onProgress: suspend (Progress) -> Unit = {},
        shouldContinue: () -> Boolean = { true },
    ): Result {
        val relevant = captures.filter { it.ssid == ssid }
        if (relevant.isEmpty()) return Result.Stopped(0, "No captures for $ssid.")

        var tried = 0
        for (candidate in candidates) {
            if (!shouldContinue()) return Result.Stopped(tried, "The time budget ran out.")
            tried++

            val pmk = WpaCrypto.pmk(candidate, ssid)
            if (pmk == null) continue

            if (relevant.any { verify(it, pmk) }) return Result.Found(candidate, tried)

            if (tried % PROGRESS_EVERY == 0) onProgress(Progress(tried, total, candidate))
        }
        return Result.Exhausted(tried)
    }

    /** True when this PMK is the one the capture was made under. */
    fun verify(capture: HandshakeCapture, pmk: ByteArray): Boolean = when (capture) {
        is HandshakeCapture.Pmkid ->
            WpaCrypto.pmkid(pmk, capture.apMac, capture.staMac).contentEquals(capture.pmkid)

        is HandshakeCapture.Eapol -> {
            val ptk = WpaCrypto.ptk(pmk, capture.apMac, capture.staMac, capture.aNonce, capture.sNonce)
            WpaCrypto.mic(WpaCrypto.kck(ptk), capture.eapolFrame, capture.keyDescriptorVersion)
                ?.contentEquals(capture.mic) == true
        }
    }

    /** Convenience for checking a single passphrase, which is what a verification run needs. */
    fun matches(capture: HandshakeCapture, passphrase: String): Boolean {
        val pmk = WpaCrypto.pmk(passphrase, capture.ssid) ?: return false
        return verify(capture, pmk)
    }

    private const val PROGRESS_EVERY = 250
}
