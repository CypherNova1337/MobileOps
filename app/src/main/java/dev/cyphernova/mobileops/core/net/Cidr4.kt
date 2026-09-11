package dev.cyphernova.mobileops.core.net

/** IPv4 CIDR arithmetic, kept free of Android types so it unit-tests on the JVM. */
object Cidr4 {

    /** Parses dotted-quad IPv4 into an unsigned 32-bit value, or null if malformed. */
    fun parseAddress(address: String): Long? {
        val octets = address.trim().split('.')
        if (octets.size != 4) return null
        var value = 0L
        for (octet in octets) {
            val n = octet.toIntOrNull() ?: return null
            if (n !in 0..255) return null
            value = (value shl 8) or n.toLong()
        }
        return value
    }

    /** Splits `a.b.c.d/nn` into its network address and prefix length. */
    fun parseBlock(cidr: String): Pair<Long, Int>? {
        val parts = cidr.trim().split('/')
        if (parts.size != 2) return null
        val base = parseAddress(parts[0]) ?: return null
        val prefix = parts[1].toIntOrNull() ?: return null
        if (prefix !in 0..32) return null
        return (base and maskOf(prefix)) to prefix
    }

    fun contains(cidr: String, address: String): Boolean {
        val (network, prefix) = parseBlock(cidr) ?: return false
        val host = parseAddress(address) ?: return false
        return (host and maskOf(prefix)) == network
    }

    /** Usable host addresses in a block, excluding network and broadcast for prefixes < 31. */
    fun hosts(cidr: String, limit: Int = 1024): List<String> {
        val (network, prefix) = parseBlock(cidr) ?: return emptyList()
        val size = 1L shl (32 - prefix)
        val first = if (prefix < 31) network + 1 else network
        val last = if (prefix < 31) network + size - 2 else network + size - 1
        if (last < first) return emptyList()
        val count = minOf(last - first + 1, limit.toLong()).toInt()
        return (0 until count).map { toDotted(first + it) }
    }

    fun toDotted(value: Long): String =
        "${(value shr 24) and 0xFF}.${(value shr 16) and 0xFF}.${(value shr 8) and 0xFF}.${value and 0xFF}"

    private fun maskOf(prefix: Int): Long =
        if (prefix == 0) 0L else (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL
}
