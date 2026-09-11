package dev.cyphernova.mobileops.core.crack

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-CMAC, as RFC 4493 defines it.
 *
 * Needed because key descriptor version 3 — the 802.11w and GCMP-era suites — signs the EAPOL
 * MIC with it rather than with an HMAC. The JCE has no CMAC provider on Android, so it is built
 * here out of the AES block cipher it does have.
 */
object AesCmac {

    fun compute(key: ByteArray, message: ByteArray): ByteArray? = runCatching {
        val secret = SecretKeySpec(key, "AES")

        // The two subkeys come from encrypting an all-zero block and shifting it, which is what
        // lets the final block be distinguished as padded or not without carrying a length.
        val l = encryptBlock(secret, ByteArray(BLOCK))
        val k1 = shiftAndMask(l)
        val k2 = shiftAndMask(k1)

        val complete = message.isNotEmpty() && message.size % BLOCK == 0
        val blocks = if (complete) message.size / BLOCK else message.size / BLOCK + 1

        val last = ByteArray(BLOCK)
        if (complete) {
            message.copyInto(last, 0, message.size - BLOCK, message.size)
            xorInto(last, k1)
        } else {
            val tail = message.copyOfRange((blocks - 1) * BLOCK, message.size)
            tail.copyInto(last)
            // RFC 4493's padding: a single set bit, then zeros.
            last[tail.size] = 0x80.toByte()
            xorInto(last, k2)
        }

        var x = ByteArray(BLOCK)
        for (index in 0 until blocks - 1) {
            val block = message.copyOfRange(index * BLOCK, (index + 1) * BLOCK)
            xorInto(block, x)
            x = encryptBlock(secret, block)
        }
        xorInto(last, x)
        encryptBlock(secret, last)
    }.getOrNull()

    private fun encryptBlock(key: SecretKeySpec, block: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(ByteArray(BLOCK)))
        return cipher.doFinal(block)
    }

    /** Left shift by one bit, then conditionally reduce by the Rb constant for GF(2^128). */
    private fun shiftAndMask(input: ByteArray): ByteArray {
        val output = ByteArray(BLOCK)
        var carry = 0
        for (index in BLOCK - 1 downTo 0) {
            val value = input[index].toInt() and 0xFF
            output[index] = ((value shl 1) or carry).toByte()
            carry = (value shr 7) and 0x01
        }
        if (input[0].toInt() and 0x80 != 0) {
            output[BLOCK - 1] = (output[BLOCK - 1].toInt() xor RB).toByte()
        }
        return output
    }

    private fun xorInto(target: ByteArray, other: ByteArray) {
        for (index in target.indices) {
            target[index] = (target[index].toInt() xor other[index].toInt()).toByte()
        }
    }

    private const val BLOCK = 16
    private const val RB = 0x87
}
