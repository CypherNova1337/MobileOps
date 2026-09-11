package dev.cyphernova.mobileops.core.radio

/**
 * Decoding for the cellular side of a survey.
 *
 * Everything here works with no WiFi, no SIM data session and no association of any kind: the
 * modem is already listening to every base station in range and the platform will hand over what
 * it heard. That makes cellular the one radio survey that still returns results in a building
 * with no wireless network at all.
 */
object CellularIntel {

    /** Radio generations, ordered so a survey can report the oldest thing the handset can see. */
    enum class Generation(val label: String, val rank: Int) {
        GSM("2G GSM", 2),
        CDMA("2G CDMA", 2),
        WCDMA("3G UMTS", 3),
        TDSCDMA("3G TD-SCDMA", 3),
        LTE("4G LTE", 4),
        NR("5G NR", 5),
        UNKNOWN("unknown", 0),
    }

    /**
     * Mobile country and network codes identify the operator of a cell before anything attaches
     * to it. Partial, same as the OUI table: an unlisted pair is reported by number.
     */
    fun operatorOf(mcc: String?, mnc: String?): String? {
        if (mcc.isNullOrBlank() || mnc.isNullOrBlank()) return null
        // MNCs are two or three digits and the leading zero is significant, so both widths are
        // tried rather than parsing to an Int and losing it.
        return OPERATORS["$mcc-$mnc"] ?: OPERATORS["$mcc-${mnc.padStart(2, '0')}"]
    }

    fun describeOperator(mcc: String?, mnc: String?): String {
        if (mcc.isNullOrBlank() || mnc.isNullOrBlank()) return "operator unidentified"
        return operatorOf(mcc, mnc) ?: "MCC $mcc / MNC $mnc (unlisted)"
    }

    /**
     * Turns a raw dBm reading into something a report can use.
     *
     * The thresholds differ by generation because the quantities are not comparable: LTE and NR
     * report RSRP, which sits roughly 20 dB below the RSSI that GSM and UMTS report for the same
     * link. Applying one scale to both would call every LTE cell weak.
     */
    fun quality(dbm: Int, generation: Generation): String {
        if (dbm == 0 || dbm == Int.MAX_VALUE) return "no reading"
        val thresholds = when (generation) {
            Generation.LTE, Generation.NR -> intArrayOf(-80, -90, -100, -110)
            else -> intArrayOf(-70, -85, -95, -105)
        }
        return when {
            dbm >= thresholds[0] -> "excellent"
            dbm >= thresholds[1] -> "good"
            dbm >= thresholds[2] -> "fair"
            dbm >= thresholds[3] -> "poor"
            else -> "barely present"
        }
    }

    /**
     * Whether the set of generations on offer leaves the handset open to a downgrade.
     *
     * 2G is the finding that matters. GSM has no mutual authentication — the handset proves
     * itself to the network and the network proves nothing back — so anything that can persuade
     * a phone onto 2G can impersonate a base station to it. A cell site broadcasting GSM in a
     * country whose operators have otherwise retired it is worth a second look, and a survey is
     * the only way to notice.
     */
    fun downgradeExposure(generations: Set<Generation>): String? = when {
        Generation.GSM in generations || Generation.CDMA in generations ->
            "2G cells are present. GSM does not authenticate the network to the handset, so a " +
                "device that can be pushed down to it can be talked to by anything claiming to " +
                "be a base station. Most operators have retired 2G; a live GSM carrier here is " +
                "either legacy infrastructure or something pretending to be it."
        Generation.WCDMA in generations || Generation.TDSCDMA in generations ->
            "3G cells are present. UMTS does authenticate both ways, but it is widely retired " +
                "and its presence alongside LTE gives a downgrade path worth noting."
        else -> null
    }

    private val OPERATORS: Map<String, String> = mapOf(
        // United States.
        "310-030" to "AT&T", "310-070" to "AT&T", "310-150" to "AT&T", "310-410" to "AT&T",
        "310-560" to "AT&T", "311-180" to "AT&T",
        "310-004" to "Verizon", "310-005" to "Verizon", "310-012" to "Verizon",
        "311-480" to "Verizon", "311-280" to "Verizon",
        "310-160" to "T-Mobile", "310-200" to "T-Mobile", "310-210" to "T-Mobile",
        "310-260" to "T-Mobile", "310-490" to "T-Mobile", "311-660" to "T-Mobile",
        "312-530" to "T-Mobile",
        "310-120" to "Sprint (T-Mobile)", "311-870" to "Boost",
        "310-020" to "Union Telephone", "313-100" to "FirstNet",
        "310-590" to "US Cellular", "311-580" to "US Cellular",
        // Canada.
        "302-220" to "Telus", "302-221" to "Telus", "302-610" to "Bell", "302-720" to "Rogers",
        // United Kingdom.
        "234-10" to "O2 UK", "234-15" to "Vodafone UK", "234-20" to "Three UK",
        "234-30" to "EE", "234-33" to "EE", "234-15x" to "Vodafone UK",
        // Western Europe.
        "262-01" to "Telekom DE", "262-02" to "Vodafone DE", "262-03" to "O2 DE",
        "208-01" to "Orange FR", "208-10" to "SFR", "208-20" to "Bouygues", "208-15" to "Free FR",
        "214-01" to "Vodafone ES", "214-03" to "Orange ES", "214-07" to "Movistar",
        "222-01" to "TIM IT", "222-10" to "Vodafone IT", "222-88" to "Wind Tre",
        // Australia and New Zealand.
        "505-01" to "Telstra", "505-02" to "Optus", "505-03" to "Vodafone AU",
        "530-01" to "One NZ", "530-05" to "Spark NZ",
    )
}
