package dev.cyphernova.mobileops.core.discovery

/**
 * NetBIOS name service, which is how a Windows or SMB host will tell you its name when reverse
 * DNS cannot.
 *
 * A node status request asks a host directly rather than asking a name server, so it works on
 * networks with no DNS records at all — which is most home and small-office networks, and the
 * reason a sweep otherwise reports a column of bare addresses.
 */
object Nbns {

    const val PORT = 137

    /**
     * The wildcard node status request. The name `*` is encoded in first-level encoding: each
     * byte becomes two, split into nibbles offset from 'A'.
     */
    fun nodeStatusRequest(transactionId: Int = 0x4D4F): ByteArray {
        val header = byteArrayOf(
            ((transactionId shr 8) and 0xFF).toByte(), (transactionId and 0xFF).toByte(),
            0x00, 0x00,             // flags: standard query
            0x00, 0x01,             // one question
            0x00, 0x00,             // no answers
            0x00, 0x00,             // no authority
            0x00, 0x00,             // no additional
        )

        // '*' followed by 15 nulls, encoded two bytes per byte.
        val name = ByteArray(16).also { it[0] = '*'.code.toByte() }
        val encoded = ByteArray(32)
        name.forEachIndexed { index, byte ->
            val value = byte.toInt() and 0xFF
            encoded[index * 2] = ('A'.code + (value shr 4)).toByte()
            encoded[index * 2 + 1] = ('A'.code + (value and 0x0F)).toByte()
        }

        return header + byteArrayOf(encoded.size.toByte()) + encoded + byteArrayOf(
            0x00,                   // end of name
            0x00, 0x21,             // type NBSTAT
            0x00, 0x01,             // class IN
        )
    }

    /** A name a host claims, and whether it claims it as a group (a workgroup or domain). */
    data class NetbiosName(val name: String, val suffix: Int, val group: Boolean) {
        /** Suffix 0x00 on a unique name is the workstation name — the one worth reporting. */
        val isWorkstation: Boolean get() = suffix == 0x00 && !group
        val isDomainOrWorkgroup: Boolean get() = suffix == 0x00 && group
        val isFileServer: Boolean get() = suffix == 0x20
    }

    /** Parses the node status response, returning every name the host claims. */
    fun parseNodeStatusResponse(data: ByteArray, length: Int = data.size): List<NetbiosName> {
        if (length < 57) return emptyList()

        // Header is 12 bytes; the answer repeats the encoded question name, then type/class/ttl
        // and a two-byte record length, after which the name count begins.
        var index = 12
        if (index >= length) return emptyList()
        val nameLength = data[index].toInt() and 0xFF
        index += 1 + nameLength + 1          // length byte, encoded name, terminator
        index += 2 + 2 + 4 + 2               // type, class, ttl, rdlength
        if (index >= length) return emptyList()

        val count = data[index].toInt() and 0xFF
        index += 1

        val names = mutableListOf<NetbiosName>()
        repeat(count) {
            if (index + 18 > length) return names
            val raw = String(data, index, 15, Charsets.US_ASCII).trim()
            val suffix = data[index + 15].toInt() and 0xFF
            val flags = ((data[index + 16].toInt() and 0xFF) shl 8) or (data[index + 17].toInt() and 0xFF)
            index += 18

            if (raw.isNotBlank() && raw.all { it.code in 0x20..0x7E }) {
                names += NetbiosName(raw, suffix, group = flags and 0x8000 != 0)
            }
        }
        return names
    }
}

/**
 * Multicast DNS, which is how Apple, Android, printers and most consumer network gear announce
 * themselves. The service enumeration query asks what service types exist rather than assuming
 * a list, so it finds things a fixed list would miss.
 */
object Mdns {

    const val PORT = 5353
    const val GROUP = "224.0.0.251"
    const val SERVICE_ENUMERATION = "_services._dns-sd._udp.local"

    fun query(name: String, type: Int = TYPE_PTR, transactionId: Int = 0): ByteArray {
        val header = byteArrayOf(
            ((transactionId shr 8) and 0xFF).toByte(), (transactionId and 0xFF).toByte(),
            0x00, 0x00,             // standard query
            0x00, 0x01,             // one question
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        )
        return header + encodeName(name) + byteArrayOf(
            ((type shr 8) and 0xFF).toByte(), (type and 0xFF).toByte(),
            0x00, 0x01,             // class IN
        )
    }

    fun encodeName(name: String): ByteArray {
        val out = ArrayList<Byte>()
        name.trim('.').split('.').filter { it.isNotEmpty() }.forEach { label ->
            val bytes = label.toByteArray(Charsets.UTF_8).take(63)
            out.add(bytes.size.toByte())
            out.addAll(bytes)
        }
        out.add(0)
        return out.toByteArray()
    }

    data class Record(val name: String, val type: Int, val target: String?)

    /**
     * Decodes the answers, following the compression pointers that make DNS messages compact and
     * parsers fragile. A pointer that loops is abandoned rather than followed forever.
     */
    fun parseResponse(data: ByteArray, length: Int = data.size): List<Record> {
        if (length < 12) return emptyList()
        val answers = ((data[6].toInt() and 0xFF) shl 8) or (data[7].toInt() and 0xFF)
        val questions = ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF)
        if (answers == 0) return emptyList()

        var index = 12
        repeat(questions) {
            index = skipName(data, index, length)
            index += 4
            if (index > length) return emptyList()
        }

        val records = mutableListOf<Record>()
        repeat(answers) {
            if (index >= length) return records
            val (name, afterName) = readName(data, index, length) ?: return records
            index = afterName
            if (index + 10 > length) return records

            val type = ((data[index].toInt() and 0xFF) shl 8) or (data[index + 1].toInt() and 0xFF)
            val rdLength = ((data[index + 8].toInt() and 0xFF) shl 8) or (data[index + 9].toInt() and 0xFF)
            index += 10
            if (index + rdLength > length) return records

            val target = when (type) {
                TYPE_PTR, TYPE_CNAME -> readName(data, index, length)?.first
                TYPE_A -> if (rdLength == 4) {
                    (0 until 4).joinToString(".") { (data[index + it].toInt() and 0xFF).toString() }
                } else {
                    null
                }
                TYPE_SRV -> if (rdLength > 6) readName(data, index + 6, length)?.first else null
                else -> null
            }
            records += Record(name, type, target)
            index += rdLength
        }
        return records
    }

    private fun skipName(data: ByteArray, start: Int, limit: Int): Int {
        var index = start
        while (index < limit) {
            val length = data[index].toInt() and 0xFF
            when {
                length == 0 -> return index + 1
                length and 0xC0 == 0xC0 -> return index + 2
                else -> index += length + 1
            }
        }
        return limit
    }

    private fun readName(data: ByteArray, start: Int, limit: Int): Pair<String, Int>? {
        val labels = mutableListOf<String>()
        var index = start
        var after = -1
        var hops = 0

        while (index < limit) {
            val length = data[index].toInt() and 0xFF
            when {
                length == 0 -> {
                    if (after < 0) after = index + 1
                    return labels.joinToString(".") to after
                }
                length and 0xC0 == 0xC0 -> {
                    if (index + 1 >= limit) return null
                    if (after < 0) after = index + 2
                    // A message can point backwards repeatedly; cap it rather than trust it.
                    if (++hops > MAX_POINTER_HOPS) return labels.joinToString(".") to after
                    index = ((length and 0x3F) shl 8) or (data[index + 1].toInt() and 0xFF)
                }
                else -> {
                    if (index + 1 + length > limit) return null
                    labels += String(data, index + 1, length, Charsets.UTF_8)
                    index += length + 1
                }
            }
        }
        return null
    }

    const val TYPE_A = 1
    const val TYPE_PTR = 12
    const val TYPE_CNAME = 5
    const val TYPE_SRV = 33
    private const val MAX_POINTER_HOPS = 16
}

/**
 * SSDP, the discovery half of UPnP. Consumer routers, media servers and cameras answer it, and
 * their replies name the product and firmware directly.
 */
object Ssdp {

    const val PORT = 1900
    const val GROUP = "239.255.255.250"

    fun mSearch(seconds: Int = 2, target: String = "ssdp:all"): ByteArray =
        (
            "M-SEARCH * HTTP/1.1\r\n" +
                "HOST: $GROUP:$PORT\r\n" +
                "MAN: \"ssdp:discover\"\r\n" +
                "MX: $seconds\r\n" +
                "ST: $target\r\n\r\n"
            ).toByteArray(Charsets.US_ASCII)

    data class Reply(val server: String?, val location: String?, val searchTarget: String?, val usn: String?)

    fun parseReply(data: ByteArray, length: Int = data.size): Reply? {
        val text = String(data, 0, length, Charsets.ISO_8859_1)
        val firstLine = text.lineSequence().firstOrNull()?.trim().orEmpty()
        if (!firstLine.startsWith("HTTP/1.1") && !firstLine.startsWith("NOTIFY")) return null

        val headers = text.lineSequence()
            .drop(1)
            .mapNotNull { line ->
                val name = line.substringBefore(':', "").trim().lowercase()
                val value = line.substringAfter(':', "").trim()
                if (name.isBlank() || value.isBlank()) null else name to value
            }
            .toMap()

        return Reply(
            server = headers["server"],
            location = headers["location"],
            searchTarget = headers["st"] ?: headers["nt"],
            usn = headers["usn"],
        )
    }
}
