package dev.cyphernova.mobileops.modules.tier0

import dev.cyphernova.mobileops.core.beacon.BeaconElements
import dev.cyphernova.mobileops.core.beacon.BeaconProfile
import dev.cyphernova.mobileops.core.evidence.Severity

/**
 * Turns raw beacon elements into findings.
 *
 * The difference from [ApSecurityAnalyser] is exploitability. That reads Android's summarised
 * capability string, which can say WPS is enabled; this reads the WPS element itself, which says
 * whether the PIN is locked — and an unlocked PIN is an attack path while a locked one is a note.
 */
object BeaconAudit {

    fun profileOf(observation: ApObservation): BeaconProfile? =
        observation.informationElements.takeIf { it.isNotEmpty() }?.let(BeaconElements::parse)

    fun issues(profile: BeaconProfile): List<SecurityIssue> = buildList {
        profile.wps?.let { wps ->
            when (wps.setupLocked) {
                false -> add(
                    SecurityIssue(
                        Severity.HIGH,
                        "WPS PIN is not locked",
                        "The AP advertises WPS with AP Setup Locked cleared, so it will keep answering " +
                            "PIN attempts. The PIN is validated in two halves, which reduces the search " +
                            "to about 11,000 guesses, and offline recovery against many chipsets is " +
                            "faster still. This is an attack path, not a hardening note.",
                    ),
                )
                true -> add(
                    SecurityIssue(
                        Severity.LOW,
                        "WPS present but PIN locked",
                        "WPS is advertised with AP Setup Locked set, so PIN attempts are refused. The " +
                            "lock is often temporary and clears on reboot — disabling WPS outright is " +
                            "the durable fix.",
                    ),
                )
                null -> Unit // The element carried no lock state; the capability-string finding stands.
            }

            if (wps.pushButtonActive) {
                add(
                    SecurityIssue(
                        Severity.HIGH,
                        "WPS push-button session active",
                        "The AP is advertising an active push-button session. Any station in range can " +
                            "associate for its duration without knowing the passphrase.",
                    ),
                )
            }

            if (wps.configured == false) {
                add(
                    SecurityIssue(
                        Severity.HIGH,
                        "AP is in its out-of-box state",
                        "WPS reports the AP as not yet configured, which usually means default " +
                            "credentials are still in place.",
                    ),
                )
            }

            val identity = listOfNotNull(
                wps.manufacturer?.let { "manufacturer $it" },
                wps.modelName?.let { "model $it" },
                wps.modelNumber?.let { "model number $it" },
                wps.serialNumber?.takeIf { it != "0" && it.length > 2 }?.let { "serial $it" },
            )
            if (identity.isNotEmpty()) {
                add(
                    SecurityIssue(
                        if (wps.serialNumber != null && wps.serialNumber.length > 2) Severity.LOW else Severity.INFO,
                        "Hardware identified from the beacon",
                        "The WPS element names this device to anyone in range: ${identity.joinToString()}. " +
                            "That is enough to look up firmware-specific vulnerabilities before " +
                            "touching the network.",
                    ),
                )
            }
        }

        profile.rsn?.let { rsn ->
            if (rsn.hasWeakCipher) {
                add(
                    SecurityIssue(
                        Severity.HIGH,
                        "Deprecated cipher offered",
                        "RSN advertises ${(rsn.pairwiseCiphers + rsn.groupCipher).distinct().joinToString()}. " +
                            "TKIP and WEP ciphers are broken and their presence lets a client be " +
                            "negotiated down onto them.",
                    ),
                )
            }

            if (rsn.isWpa3Transition) {
                add(
                    SecurityIssue(
                        Severity.LOW,
                        "WPA3 transition mode confirmed in RSN",
                        "The AKM list offers both ${rsn.akmSuites.joinToString()}, so SAE's protection " +
                            "against offline dictionary attack can be sidestepped by negotiating PSK.",
                    ),
                )
            }

            if (!rsn.managementFrameProtectionRequired && rsn.managementFrameProtectionCapable) {
                add(
                    SecurityIssue(
                        Severity.LOW,
                        "802.11w supported but not required",
                        "The AP can protect management frames and does not insist on it, so a client " +
                            "that declines still runs unprotected and remains deauthenticable.",
                    ),
                )
            }

            if (rsn.preAuthentication) {
                add(
                    SecurityIssue(
                        Severity.INFO,
                        "RSN pre-authentication enabled",
                        "Pre-authentication is advertised. It speeds roaming and widens the surface " +
                            "reachable before association.",
                    ),
                )
            }
        }

        if (profile.legacyWpaPresent && profile.rsn != null) {
            add(
                SecurityIssue(
                    Severity.MEDIUM,
                    "Legacy WPA offered alongside WPA2",
                    "Both a WPA vendor element and an RSN element are present, so the AP still accepts " +
                        "original WPA. Clients can be steered onto the weaker of the two.",
                ),
            )
        }
    }

    /** A one-line summary of the radio capabilities the elements advertise. */
    fun radioSummary(profile: BeaconProfile): String = buildList {
        if (profile.supportsHt) add("802.11n")
        if (profile.supportsVht) add("802.11ac")
        if (profile.supportsHe) add("802.11ax")
    }.joinToString().ifBlank { "802.11a/b/g only" }
}
