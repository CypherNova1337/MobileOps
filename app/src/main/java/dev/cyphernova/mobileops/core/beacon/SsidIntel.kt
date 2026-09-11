package dev.cyphernova.mobileops.core.beacon

/**
 * Reads meaning out of a network name.
 *
 * An SSID is broadcast to everyone in range and costs nothing to collect, yet it is routinely the
 * most informative thing about a network you have not touched. It says who supplied the router,
 * whether anyone ever changed its defaults, what kind of device is behind it, and often who owns
 * the place. None of that requires association, a passphrase, or even a working network — which
 * makes it the densest intelligence available from a car park.
 *
 * The judgements here are deliberately conservative. An unchanged factory SSID is evidence that
 * nobody went into the admin interface, not proof of a weak key, and it is reported that way.
 */
object SsidIntel {

    enum class Weight { NOTE, CONCERN }

    data class Note(val label: String, val detail: String, val weight: Weight)

    /** One factory naming scheme and what it implies. */
    private data class Scheme(
        val pattern: Regex,
        val vendor: String,
        val detail: String,
        val weight: Weight = Weight.CONCERN,
    )

    fun classify(ssid: String): List<Note> {
        if (ssid.isBlank()) return emptyList()
        val notes = mutableListOf<Note>()

        SCHEMES.firstOrNull { it.pattern.containsMatchIn(ssid) }?.let { scheme ->
            notes += Note(
                label = "Factory SSID — ${scheme.vendor}",
                detail = scheme.detail,
                weight = scheme.weight,
            )
        }

        DEVICE_HINTS.firstOrNull { it.first.containsMatchIn(ssid) }?.let { (_, description) ->
            notes += Note(
                label = "Device type disclosed",
                detail = description,
                weight = Weight.NOTE,
            )
        }

        SEGMENT_HINTS.firstOrNull { it.first.containsMatchIn(ssid) }?.let { (_, description) ->
            notes += Note(
                label = "Network role disclosed",
                detail = description,
                weight = Weight.NOTE,
            )
        }

        if (looksPersonal(ssid)) {
            notes += Note(
                label = "Personal identifier in the name",
                detail = "The SSID appears to carry a person's name or a household. That is " +
                    "broadcast continuously to the street and ties a physical address to an " +
                    "individual without anyone connecting to anything.",
                weight = Weight.NOTE,
            )
        }

        return notes
    }

    /**
     * Whether the name is an untouched factory default.
     *
     * This is the finding worth acting on. Several ISP-supplied routers derive their default
     * WPA key from the same serial number the SSID suffix comes from, so an unchanged name
     * narrows an offline key search from impossible to enumerable — and regardless of the key,
     * it is strong evidence the admin password is still on its factory value too.
     */
    fun isFactoryDefault(ssid: String): Boolean = SCHEMES.any { it.pattern.containsMatchIn(ssid) }

    fun vendorFromSsid(ssid: String): String? =
        SCHEMES.firstOrNull { it.pattern.containsMatchIn(ssid) }?.vendor

    /**
     * Whether a name reads as a person's rather than a product's.
     *
     * A possessive is decisive. Beyond that it takes *two* letters-only words, because one word
     * next to a serial is how every ISP names a gateway — "TMOBILE-5271" and "MyAltice 0234a3"
     * both split into a word and a hex blob, and calling those a household was wrong. Two
     * letter-only words next to each other is what a name actually looks like.
     *
     * Kept crude on purpose: the alternative is a list of first names, which would be worse and
     * would still miss every name not on it.
     */
    private fun looksPersonal(ssid: String): Boolean {
        if (isFactoryDefault(ssid)) return false
        if (ssid.contains('\'')) return true
        val words = ssid.split(' ', '-', '_', '.')
            .filter { it.length > 2 }
            // A part containing a digit is a serial or a model number, not part of a name.
            .filter { word -> word.all(Char::isLetter) }
        // Carrier and vendor tokens are branding wherever they appear, so they are dropped
        // rather than disqualifying the name — "Smith Family Home" is still a household.
        val remaining = words.filterNot { it.uppercase() in BRAND_WORDS }
        return remaining.count { it.first().isUpperCase() } >= 2
    }

    /**
     * Words that turn up in equipment and network names and are never the finding. Uppercased at
     * comparison time so case in the SSID does not matter.
     */
    private val BRAND_WORDS = setOf(
        "TMOBILE", "MOBILE", "ALTICE", "MYALTICE", "OPTIMUM", "VERIZON", "XFINITY", "COMCAST",
        "SPECTRUM", "CENTURYLINK", "FRONTIER", "COX", "STARLINK", "NETGEAR", "ORBI", "LINKSYS",
        "ASUS", "TPLINK", "DLINK", "BELKIN", "UBIQUITI", "UNIFI", "EERO", "DECO", "GOOGLE",
        "NEST", "WIFI", "NETWORK", "GUEST", "HOTSPOT", "SETUP", "HOME", "INTERNET", "FIBER",
        "GATEWAY", "ROUTER", "EXTENDER", "REPEATER", "MESH",
    )

    private val SCHEMES = listOf(
        Scheme(
            Regex("""^NETGEAR\d*$""", RegexOption.IGNORE_CASE), "Netgear",
            "Netgear ships this name with a printed default passphrase on the underside of the " +
                "router. It being unchanged means nobody opened the admin interface, so the " +
                "admin credentials are very likely factory too.",
        ),
        Scheme(
            Regex("""^(Linksys|Cisco)\d*(_\w+)?$""", RegexOption.IGNORE_CASE), "Linksys",
            "An unchanged Linksys factory name. Older firmware shipped with a blank or 'admin' " +
                "administrative password on this default.",
        ),
        Scheme(
            Regex("""^(TP-?Link|TP-LINK)[_-]?\w*$""", RegexOption.IGNORE_CASE), "TP-Link",
            "TP-Link's factory name embeds the last digits of the BSSID. The default admin " +
                "credential on this generation is admin/admin.",
        ),
        Scheme(
            Regex("""^(ASUS|RT-AC|RT-AX)\w*$""", RegexOption.IGNORE_CASE), "ASUS",
            "An unchanged ASUS factory name; the router was likely set up by accepting defaults.",
        ),
        Scheme(
            Regex("""^(dlink|D-?Link)[-_]?\w*$""", RegexOption.IGNORE_CASE), "D-Link",
            "An unchanged D-Link factory name.",
        ),
        Scheme(
            Regex("""^belkin\.\w+$""", RegexOption.IGNORE_CASE), "Belkin",
            "Belkin's factory name suffix is derived from the device serial, which older models " +
                "also derived their default WPA key from.",
        ),
        Scheme(
            Regex("""^ATT\w{4,}$|^ATT-WiFi-\w+$""", RegexOption.IGNORE_CASE), "AT&T",
            "An AT&T-supplied gateway on its factory SSID. The default passphrase is printed on " +
                "the unit and is commonly left in place.",
        ),
        Scheme(
            Regex("""^(SpectrumSetup|MySpectrumWiFi)[-\w]*$""", RegexOption.IGNORE_CASE), "Spectrum",
            "A Spectrum-supplied gateway still on its factory name and, by implication, its " +
                "printed default key.",
        ),
        Scheme(
            Regex("""^(HOME-\w{4}|xfinitywifi|XFINITY)$""", RegexOption.IGNORE_CASE), "Comcast",
            "A Comcast gateway on its factory name. 'xfinitywifi' in particular is the open " +
                "community hotspot broadcast from a subscriber's own router.",
        ),
        Scheme(
            Regex("""^(CenturyLink|Frontier|Verizon_)\w*$""", RegexOption.IGNORE_CASE), "US ISP",
            "An ISP-supplied gateway on its factory name, implying untouched default credentials.",
        ),
        Scheme(
            Regex("""^TMOBILE[-_]?\w{4,}$""", RegexOption.IGNORE_CASE), "T-Mobile",
            "A T-Mobile home internet gateway on its factory name. The suffix is taken from the " +
                "unit's serial and the printed default key sits beside it on the same label.",
        ),
        Scheme(
            Regex("""^(MyAltice|Altice|Optimum)[ _-]?\w*$""", RegexOption.IGNORE_CASE), "Altice",
            "An Altice/Optimum-supplied gateway on its factory name, with the suffix derived from " +
                "the unit. Untouched name, very likely untouched admin credentials.",
        ),
        Scheme(
            Regex("""^(Cox|Panoramic|COX-)\w*Wifi\w*$""", RegexOption.IGNORE_CASE), "Cox",
            "A Cox-supplied gateway on its factory name.",
        ),
        Scheme(
            Regex("""^(BTHub\w*|BTWifi[-\w]*|SKY\w{4,}|TALKTALK[-\w]+|VM\d{6,}|EE-\w+)$""", RegexOption.IGNORE_CASE),
            "UK ISP",
            "A UK ISP-supplied router on its factory name. Several of these generations derive " +
                "the default key from the serial, which makes an offline search tractable.",
        ),
        Scheme(
            Regex("""^(SETUP-\w{4}|ZyXEL\w*|Actiontec\w*|Arris\w*|MOTOROLA[-\w]*)$""", RegexOption.IGNORE_CASE),
            "OEM default",
            "An OEM factory name, typically from a router that was plugged in and never " +
                "configured further.",
        ),
        Scheme(
            Regex("""^DIRECT-\w{2}[-_]""", RegexOption.IGNORE_CASE), "WiFi Direct",
            "A WiFi Direct or Miracast advertisement rather than an infrastructure network — a " +
                "printer, television or casting receiver offering a peer-to-peer link. These " +
                "frequently accept connections with a fixed PIN or none at all.",
            weight = Weight.NOTE,
        ),
    )

    private val DEVICE_HINTS = listOf(
        Regex("""HP-Print|ENVY|OfficeJet|LaserJet|Brother|EPSON|Canon""", RegexOption.IGNORE_CASE) to
            "A printer broadcasting its own network. Printer web interfaces are routinely " +
                "unauthenticated and hold scanned documents, address books and stored credentials.",
        Regex("""Chromecast|Roku|FireTV|SHIELD|AppleTV|Samsung\s?TV|LG_?TV""", RegexOption.IGNORE_CASE) to
            "A media device. These advertise control APIs that usually require no authentication " +
                "on the local segment.",
        Regex("""Ring|Wyze|Arlo|Nest|Blink|Reolink|Hikvision|Dahua""", RegexOption.IGNORE_CASE) to
            "A camera or smart-home device, which places a recording device on the network and " +
                "often a cloud tunnel outbound from it.",
        Regex("""Sonos|Bose|Denon|Yamaha""", RegexOption.IGNORE_CASE) to
            "An audio device with an unauthenticated local control API.",
        Regex("""Tesla|Rivian|BMW|MyCar|Ford""", RegexOption.IGNORE_CASE) to
            "A vehicle hotspot, which tends to indicate the owner is physically present.",
        Regex("""iPhone|Android\w*Hotspot|Galaxy|Pixel|.*'s\s?(iPhone|Phone)""", RegexOption.IGNORE_CASE) to
            "A phone hotspot. It moves with its owner, so the same name reappearing later places " +
                "a specific person at a specific time.",
    )

    private val SEGMENT_HINTS = listOf(
        Regex("""[-_ ](guest|visitor|public)\b|^guest""", RegexOption.IGNORE_CASE) to
            "Named as a guest network. Guest SSIDs are worth confirming are actually isolated — " +
                "the name asserts segmentation that is often not implemented.",
        Regex("""\b(corp|corporate|internal|staff|employee|admin|IT)\b""", RegexOption.IGNORE_CASE) to
            "Named as an internal or corporate network, which marks it as the higher-value " +
                "segment without anyone needing to probe for that.",
        Regex("""\b(VOIP|SCADA|PLC|ICS|POS|CCTV|CAM|IOT|MGMT|MGMT)\b""", RegexOption.IGNORE_CASE) to
            "The name discloses the network's purpose. A separate SSID for control, payment or " +
                "camera systems tells an outsider exactly which one matters before they are on it.",
        Regex("""\b(hospital|clinic|school|library|police|fire|bank)\b""", RegexOption.IGNORE_CASE) to
            "The name identifies the operating organisation and its sector.",
        Regex(
            """\b(biomed|clinical|telemetry|tele|nursecall|nurse|pyxis|omnicell|alaris|
                |epic|cerner|meditech|pacs|radiology|imaging|infusion|patient|ward|theatre|icu)\b"""
                .trimMargin().replace("\n", ""),
            RegexOption.IGNORE_CASE,
        ) to
            "The name marks this as a clinical or biomedical network. That is the segment " +
                "carrying patient data and connected medical equipment, and naming it says so to " +
                "anyone in the car park — an SSID is the one thing a network broadcasts to people " +
                "who have no access to it at all.",
        Regex(
            """\b(bms|bas|hvac|chiller|boiler|plant|scada|plc|ot|process|energy|
                |lighting|access|badge|door|elevator|lift)\b""".trimMargin().replace("\n", ""),
            RegexOption.IGNORE_CASE,
        ) to
            "The name marks this as building management or operational technology. Those " +
                "networks run physical systems and are routinely flat and unauthenticated " +
                "underneath, on the assumption nobody can reach them.",
    )
}
