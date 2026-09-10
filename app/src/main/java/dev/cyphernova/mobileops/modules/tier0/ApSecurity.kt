package dev.cyphernova.mobileops.modules.tier0

import dev.cyphernova.mobileops.core.evidence.Severity

/** Link-layer protection offered by an AP, strongest match wins. */
enum class Encryption(val label: String) {
    OPEN("Open"),
    OWE("OWE (Enhanced Open)"),
    WEP("WEP"),
    WPA("WPA (TKIP-era)"),
    WPA2("WPA2"),
    WPA2_ENTERPRISE("WPA2-Enterprise"),
    WPA3("WPA3 (SAE)"),
    WPA3_TRANSITION("WPA3 transition (SAE + PSK)"),
    WPA3_ENTERPRISE("WPA3-Enterprise"),
}

/** The verdict on one AP's advertised capabilities. */
data class SecurityProfile(
    val encryption: Encryption,
    val wpsEnabled: Boolean,
    val managementFrameProtection: Boolean,
    val issues: List<SecurityIssue>,
)

data class SecurityIssue(
    val severity: Severity,
    val title: String,
    val detail: String,
)

/**
 * Reads the capability string a beacon advertises. This is the honest limit of what a stock
 * Android device can assess about an AP: everything here is derived from frames the AP is
 * already broadcasting to the whole room, so it is entirely passive.
 */
object ApSecurityAnalyser {

    fun analyse(observation: ApObservation): SecurityProfile {
        val caps = observation.capabilities.uppercase()
        val wps = caps.contains("WPS")
        // MFPC = capable, MFPR = required. WPA3 mandates it; WPA2 rarely turns it on.
        val pmf = caps.contains("MFPR") || caps.contains("MFPC")
        val encryption = classify(caps)
        val issues = buildList {
            when (encryption) {
                Encryption.OPEN -> add(
                    SecurityIssue(
                        Severity.HIGH,
                        "Unencrypted network",
                        "The AP offers no link-layer encryption, so every frame is readable by anyone in range.",
                    ),
                )
                Encryption.WEP -> add(
                    SecurityIssue(
                        Severity.CRITICAL,
                        "WEP encryption",
                        "WEP's RC4 keystream reuse has been trivially breakable since 2001; treat this network as open.",
                    ),
                )
                Encryption.WPA -> add(
                    SecurityIssue(
                        Severity.HIGH,
                        "Legacy WPA/TKIP",
                        "Original WPA with TKIP is deprecated and vulnerable to known key-recovery attacks.",
                    ),
                )
                Encryption.WPA3_TRANSITION -> add(
                    SecurityIssue(
                        Severity.LOW,
                        "WPA3 transition mode",
                        "The AP accepts both SAE and PSK, so a client can be pushed onto the weaker PSK path.",
                    ),
                )
                else -> Unit
            }
            if (wps) {
                add(
                    SecurityIssue(
                        Severity.HIGH,
                        "WPS enabled",
                        "WPS PIN exchange splits the 8-digit PIN into two halves, cutting the search space to ~11,000 " +
                            "guesses. Disable WPS on the AP.",
                    ),
                )
            }
            if (!pmf && encryption != Encryption.OPEN) {
                add(
                    SecurityIssue(
                        Severity.LOW,
                        "No management frame protection",
                        "Without 802.11w, management frames are unauthenticated, leaving clients exposed to " +
                            "deauthentication and evil-twin steering.",
                    ),
                )
            }
            if (observation.isHidden) {
                add(
                    SecurityIssue(
                        Severity.INFO,
                        "Hidden SSID",
                        "The SSID is not broadcast, but connected clients still probe for it by name — this is not " +
                            "a security control.",
                    ),
                )
            }
        }
        return SecurityProfile(encryption, wps, pmf, issues)
    }

    private fun classify(caps: String): Encryption = when {
        caps.contains("SAE") && caps.contains("WPA2-PSK") -> Encryption.WPA3_TRANSITION
        caps.contains("SAE") && caps.contains("EAP") -> Encryption.WPA3_ENTERPRISE
        caps.contains("SAE") -> Encryption.WPA3
        caps.contains("RSN-EAP") || caps.contains("WPA2-EAP") -> Encryption.WPA2_ENTERPRISE
        caps.contains("RSN") || caps.contains("WPA2") -> Encryption.WPA2
        caps.contains("OWE") -> Encryption.OWE
        caps.contains("WPA") -> Encryption.WPA
        caps.contains("WEP") -> Encryption.WEP
        else -> Encryption.OPEN
    }
}
