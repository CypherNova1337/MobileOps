package dev.cyphernova.mobileops.core.capture

/** Identifies one conversation. The four-tuple is what NAT and the relays key off. */
data class FlowKey(
    val sourceIp: Int,
    val sourcePort: Int,
    val destinationIp: Int,
    val destinationPort: Int,
) {
    override fun toString(): String =
        "${Packets.ipToString(sourceIp)}:$sourcePort → " +
            "${Packets.ipToString(destinationIp)}:$destinationPort"
}
