package dev.cyphernova.mobileops.core.attack

/**
 * Assesses 802.1X wireless, where the weakness is almost never the network.
 *
 * Enterprise WiFi has no shared passphrase, so everything the PSK analysis does is irrelevant to
 * it — and a tool that stops there concludes an enterprise network is fine, which is close to
 * backwards. The exposure moved rather than disappearing: it now sits in the client's supplicant
 * configuration and in what the RADIUS exchange gives away, neither of which is visible in a
 * beacon.
 *
 * What a beacon *does* settle is the shape of the problem — which authentication suites are on
 * offer, whether the same network name is also served by something weaker, and whether
 * management frames are protected. Those three decide how much the client-side question matters,
 * and all three are readable without associating.
 */
object EnterpriseWifi {

    /** How an SSID's radios authenticate, taken together rather than one at a time. */
    data class Posture(
        val ssid: String,
        /** Every AKM suite offered anywhere under this name. */
        val akmSuites: Set<String>,
        /** BSSIDs offering 802.1X. */
        val enterpriseBssids: List<String>,
        /** BSSIDs under the same name offering a pre-shared key instead. */
        val personalBssids: List<String>,
        val managementFrameProtectionRequired: Boolean,
        val managementFrameProtectionCapable: Boolean,
    ) {
        val isEnterprise: Boolean get() = enterpriseBssids.isNotEmpty()

        /**
         * The same name served by both 802.1X and a pre-shared key.
         *
         * This is the finding worth walking the building for. A client configured for the
         * enterprise profile will happily associate to whichever BSSID answers, and the weaker
         * one is a passphrase — which puts the whole network behind a secret that can be captured
         * and cracked offline, regardless of how carefully the RADIUS side was built.
         */
        val hasPersonalFallback: Boolean get() = isEnterprise && personalBssids.isNotEmpty()

        /** Suite B at 192 bits mandates PMF and certificate-based EAP, so it changes the advice. */
        val isSuiteB: Boolean get() = akmSuites.any { it.contains("SuiteB") }
    }

    /** One thing worth saying about an enterprise deployment. */
    data class Note(val severity: Level, val title: String, val detail: String)

    enum class Level { INFO, LOW, MEDIUM, HIGH, CRITICAL }

    fun assess(posture: Posture): List<Note> = buildList {
        if (!posture.isEnterprise) return@buildList

        add(
            Note(
                Level.INFO,
                "802.1X in use",
                "Authentication is ${posture.akmSuites.joinToString()} across " +
                    "${posture.enterpriseBssids.size} BSSID(s). There is no shared passphrase to " +
                    "capture or crack, so the offline attack that works against WPA2-PSK does " +
                    "not apply here. The exposure moved to the client rather than going away.",
            ),
        )

        if (posture.hasPersonalFallback) {
            add(
                Note(
                    Level.CRITICAL,
                    "The same network name is also served with a pre-shared key",
                    "'${posture.ssid}' is offered as 802.1X on " +
                        "${posture.enterpriseBssids.joinToString()} and as a pre-shared key on " +
                        "${posture.personalBssids.joinToString()}. A client configured for this " +
                        "network will associate to whichever radio answers, so the whole " +
                        "deployment is only as strong as that passphrase — which can be captured " +
                        "and cracked offline. Everything the RADIUS infrastructure does is " +
                        "bypassed by walking to wherever the weaker radio is loudest.",
                ),
            )
        }

        add(certificateValidationNote(posture))

        if (!posture.managementFrameProtectionRequired) {
            add(
                Note(
                    if (posture.managementFrameProtectionCapable) Level.MEDIUM else Level.HIGH,
                    if (posture.managementFrameProtectionCapable) {
                        "802.11w offered but not required"
                    } else {
                        "No management frame protection"
                    },
                    "Clients can be deauthenticated, which matters more here than on a personal " +
                        "network: forcing a reassociation produces a fresh EAP exchange for " +
                        "anyone listening. On PEAP or EAP-TTLS that exchange carries the outer " +
                        "identity in the clear and an MSCHAPv2 challenge-response that can be " +
                        "attacked offline. Requiring 802.11w removes the ability to provoke it " +
                        "on demand.",
                ),
            )
        }

        if (posture.isSuiteB) {
            add(
                Note(
                    Level.INFO,
                    "Suite B profile in use",
                    "The 192-bit profile mandates certificate-based EAP and management frame " +
                        "protection, which closes the credential-relay path by construction. " +
                        "This is the configuration the notes above are asking for.",
                ),
            )
        }
    }

    /**
     * The finding that actually matters on enterprise wireless, and the one a beacon cannot
     * settle — so it is stated as what to verify rather than as a result.
     *
     * Nothing an unassociated observer can see says whether clients validate the RADIUS server's
     * certificate. That single setting is the difference between a network that resists a rogue
     * access point and one that hands over a domain credential to it.
     */
    private fun certificateValidationNote(posture: Posture) = Note(
        if (posture.isSuiteB) Level.LOW else Level.HIGH,
        "Client certificate validation cannot be confirmed from outside",
        "An 802.1X network's real question is whether its clients check the RADIUS server's " +
            "certificate before sending credentials to it. Where they do not — and on estates " +
            "configured by hand rather than by policy, they frequently do not — a rogue access " +
            "point with the same SSID collects the outer identity and an MSCHAPv2 " +
            "challenge-response, which is crackable offline into the domain password behind it. " +
            "\n\nThis is not observable from a beacon and this handset cannot test it: standing " +
            "up a convincing clone needs a SoftAP with a chosen SSID and a RADIUS server behind " +
            "it, and the platform gives an app no control over the hotspot SSID. Verify it on " +
            "the client side instead — the supplicant profile must pin a CA certificate and a " +
            "server name, and on managed devices that must come from policy rather than from " +
            "whoever first joined the network.",
    )

    /**
     * The routes an enterprise network offers, for the attack-path analysis.
     *
     * Deliberately honest that the interesting one is out of reach here. A rogue-RADIUS attack is
     * entirely practical with a laptop and a supported radio, and saying so is more useful than
     * omitting it — it tells the operator what to bring.
     */
    fun routesFor(posture: Posture): List<AttackPath.Route> = buildList {
        if (!posture.isEnterprise) return@buildList

        if (posture.hasPersonalFallback) {
            add(
                AttackPath.Route(
                    name = "Associate to the pre-shared key radio instead",
                    viability = AttackPath.Viability.NEEDS_CAPTURE,
                    rationale = "The same SSID is served with a pre-shared key on " +
                        "${posture.personalBssids.joinToString()}. That path has a passphrase, " +
                        "and a passphrase can be recovered offline — which routes around the " +
                        "802.1X infrastructure completely.",
                    requires = "a handshake from the pre-shared key BSSID",
                    module = "t0.crack.handshake",
                ),
            )
        }

        add(
            AttackPath.Route(
                name = "Rogue RADIUS / credential relay",
                viability = AttackPath.Viability.BLOCKED,
                rationale = "Where clients do not validate the RADIUS server certificate, an " +
                    "access point answering to this SSID collects the outer identity and an " +
                    "MSCHAPv2 challenge-response, which cracks offline into the credential " +
                    "behind it. This is the standard attack on enterprise wireless and it is " +
                    "entirely practical — just not from a handset, which cannot choose its own " +
                    "SoftAP SSID.",
                requires = "a host running hostapd-wpe or eaphammer against an adapter it controls",
            ),
        )

        add(
            AttackPath.Route(
                name = "EAP identity harvesting",
                viability = AttackPath.Viability.BLOCKED,
                rationale = if (posture.managementFrameProtectionRequired) {
                    "The outer identity in a PEAP or TTLS exchange travels in the clear, but this " +
                        "network requires 802.11w, so reassociations cannot be provoked — a " +
                        "listener would have to wait for clients to connect of their own accord."
                } else {
                    "The outer identity in a PEAP or TTLS exchange travels in the clear, and this " +
                        "network does not require 802.11w, so clients can be deauthenticated to " +
                        "produce exchanges on demand. That yields valid usernames, which is where " +
                        "password spraying starts."
                },
                requires = "monitor mode to hear the exchange, and injection to provoke one",
            ),
        )
    }
}
