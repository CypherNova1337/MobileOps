package dev.cyphernova.mobileops.core.crack

import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * The cryptography that turns a captured WPA2 handshake and a candidate passphrase into a
 * yes or no.
 *
 * WPA2-PSK has no online weakness worth the name — the four-way handshake is exactly as strong
 * as the passphrase behind it. What it does have is an *offline* one: every value an attacker
 * needs to test a guess travels in the clear. The nonces, the MAC addresses and the MIC are all
 * visible to anyone listening, so once a handshake is captured the search runs at whatever speed
 * the hardware manages, with nothing on the network able to notice or rate-limit it.
 *
 * That is why the cost is where it is. The PMK derivation is 4096 rounds of HMAC-SHA1 salted
 * with the SSID, which is deliberate: it buys roughly four thousand times the work per guess.
 * Everything after it is cheap, which is what makes the ordering here matter — the PMK is
 * computed once per passphrase and reused against every handshake in the file.
 */
object WpaCrypto {

    const val PMK_BYTES = 32
    private const val PBKDF2_ROUNDS = 4096

    /**
     * The pairwise master key: PBKDF2-HMAC-SHA1 over the passphrase, salted with the SSID.
     *
     * The SSID being the salt is why a rainbow table has to be built per network, and why the
     * common SSIDs have precomputed tables while an unusual one does not.
     */
    fun pmk(passphrase: String, ssid: String): ByteArray? = runCatching {
        // The standard admits 8 to 63 printable characters; outside that the AP would not have
        // accepted it either, so testing it is wasted work.
        if (passphrase.length !in 8..63) return null
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
        val spec = PBEKeySpec(
            passphrase.toCharArray(),
            ssid.toByteArray(Charsets.UTF_8),
            PBKDF2_ROUNDS,
            PMK_BYTES * 8,
        )
        factory.generateSecret(spec).encoded
    }.getOrNull()

    /**
     * The 802.11i pseudo-random function, which expands the PMK into the per-session keys.
     *
     * Counter-mode HMAC-SHA1: the counter byte sits at the *end* of each block's input, which is
     * the detail that separates a working implementation from one that derives plausible-looking
     * keys that never verify.
     */
    fun prf(key: ByteArray, label: String, data: ByteArray, outputBits: Int): ByteArray {
        val labelBytes = label.toByteArray(Charsets.US_ASCII)
        val outputBytes = outputBits / 8
        val blocks = (outputBytes + 19) / 20
        val accumulated = ByteArray(blocks * 20)
        for (index in 0 until blocks) {
            val input = labelBytes + byteArrayOf(0) + data + byteArrayOf(index.toByte())
            hmacSha1(key, input).copyInto(accumulated, index * 20)
        }
        return accumulated.copyOfRange(0, outputBytes)
    }

    /**
     * The pairwise transient key. Only its first sixteen bytes — the key confirmation key —
     * are needed to check a guess, but the whole thing is derived because the layout is what
     * makes the offsets meaningful.
     *
     * Both the addresses and the nonces are sorted before hashing, so that the two sides derive
     * the same key without having to agree who goes first.
     */
    fun ptk(
        pmk: ByteArray,
        apMac: ByteArray,
        staMac: ByteArray,
        aNonce: ByteArray,
        sNonce: ByteArray,
    ): ByteArray {
        val data = minOf(apMac, staMac) + maxOf(apMac, staMac) +
            minOf(aNonce, sNonce) + maxOf(aNonce, sNonce)
        return prf(pmk, "Pairwise key expansion", data, PTK_BITS)
    }

    /** The key confirmation key, which is what signs the MIC. */
    fun kck(ptk: ByteArray): ByteArray = ptk.copyOfRange(0, 16)

    /**
     * Recomputes the MIC over an EAPOL-Key frame.
     *
     * Which algorithm signs it is carried in the low three bits of the key information field, and
     * getting that wrong is the most common reason a correct passphrase appears to fail: WPA with
     * TKIP signs with HMAC-MD5, WPA2 with CCMP uses HMAC-SHA1 truncated to sixteen bytes, and
     * 802.11w-era suites use AES-CMAC.
     *
     * @param eapol the whole frame from the 802.1X version byte, with the MIC field zeroed.
     */
    fun mic(kck: ByteArray, eapol: ByteArray, keyDescriptorVersion: Int): ByteArray? = when (keyDescriptorVersion) {
        1 -> hmacMd5(kck, eapol)
        2 -> hmacSha1(kck, eapol).copyOfRange(0, 16)
        3 -> AesCmac.compute(kck, eapol)
        else -> null
    }

    /**
     * The PMKID, which is a far cheaper thing to attack than a handshake.
     *
     * It is derived from the PMK alone, so it needs no client and no four-way exchange — an AP
     * that volunteers one in its first association response hands over a verifiable target to
     * anybody who asks, without a single legitimate user being present.
     */
    fun pmkid(pmk: ByteArray, apMac: ByteArray, staMac: ByteArray): ByteArray =
        hmacSha1(pmk, "PMK Name".toByteArray(Charsets.US_ASCII) + apMac + staMac)
            .copyOfRange(0, 16)

    fun hmacSha1(key: ByteArray, data: ByteArray): ByteArray = hmac("HmacSHA1", key, data)

    fun hmacMd5(key: ByteArray, data: ByteArray): ByteArray = hmac("HmacMD5", key, data)

    private fun hmac(algorithm: String, key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(algorithm)
        mac.init(SecretKeySpec(key, algorithm))
        return mac.doFinal(data)
    }

    /** Unsigned comparison — a MAC address byte above 0x7F must not sort as negative. */
    private fun minOf(a: ByteArray, b: ByteArray): ByteArray = if (compare(a, b) <= 0) a else b

    private fun maxOf(a: ByteArray, b: ByteArray): ByteArray = if (compare(a, b) > 0) a else b

    private fun compare(a: ByteArray, b: ByteArray): Int {
        for (index in 0 until minOf(a.size, b.size)) {
            val difference = (a[index].toInt() and 0xFF) - (b[index].toInt() and 0xFF)
            if (difference != 0) return difference
        }
        return a.size - b.size
    }

    /** KCK (128) + KEK (128) + TK (128) for CCMP. */
    private const val PTK_BITS = 384
}
