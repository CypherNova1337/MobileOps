package dev.cyphernova.mobileops.core.attack

/**
 * Works out how a given network could actually be entered, and what each route costs.
 *
 * This exists because a list of weaknesses is not a WiFi assessment. "WPS is enabled" and
 * "802.11w is optional" are true statements that do not, on their own, tell an operator whether
 * they are getting onto the network this afternoon or not at all. What decides that is which
 * routes are open, what each one needs that they may not have, and which is cheapest.
 *
 * The analysis is deliberately honest about the handset. Most published WiFi attacks need to
 * transmit or receive raw 802.11 frames, and Android has never exposed monitor mode or injection
 * to an app at any patch level. A tool that lists those as available routes is lying to its
 * operator, so they are listed as blocked with the reason — which is itself useful, because it
 * says exactly what hardware would change the answer.
 */
object AttackPath {

    /** How close a route is to actually working, in the order an operator would try them. */
    enum class Viability(val label: String, val rank: Int) {
        /** Usable right now from this handset, with what is already known. */
        OPEN("Open now", 0),

        /** Usable once the handset has an IP on the network — a pivot, not an entry. */
        NEEDS_ACCESS("Needs LAN access first", 1),

        /** Usable once a capture is supplied from hardware that can collect one. */
        NEEDS_CAPTURE("Needs a capture from other hardware", 2),

        /** Not reachable from this device, with the reason attached. */
        BLOCKED("Blocked on this device", 3),

        /** The target's configuration closes this one regardless of hardware. */
        NOT_APPLICABLE("Not applicable to this target", 4),
    }

    /**
     * One way in.
     *
     * @param requires what the operator must obtain or do before this route runs.
     * @param module the module that executes it, where one exists.
     */
    data class Route(
        val name: String,
        val viability: Viability,
        val rationale: String,
        val requires: String? = null,
        val module: String? = null,
    )

    /** Everything the analysis needs to know about a target, gathered from passive observation. */
    data class Target(
        val ssid: String,
        val bssid: String,
        val isOpen: Boolean,
        val isWep: Boolean,
        /** True when a passphrase-derived key is in play — WPA, WPA2-PSK, or WPA3 transition. */
        val hasPresharedKey: Boolean,
        /** True when SAE is the only AKM offered, which defeats offline dictionary attack. */
        val isSaeOnly: Boolean,
        val isEnterprise: Boolean,
        val wpsAdvertised: Boolean,
        /** Null when the beacon did not carry the WPS lock state. */
        val wpsPinLocked: Boolean? = null,
        val wpsPushButtonActive: Boolean = false,
        val managementFrameProtectionRequired: Boolean = false,
        val factoryDefaultSsid: Boolean = false,
        val haveCapture: Boolean = false,
        val haveLanAccess: Boolean = false,
    )

    /** The routes for one target, cheapest first. */
    fun routesFor(target: Target): List<Route> = buildList {
        add(openNetwork(target))
        add(wpsPushButton(target))
        add(wpsOverUpnp(target))
        add(offlineCrack(target))
        add(pmkid(target))
        add(wpsOverAir(target))
        add(handshakeCapture(target))
        add(evilTwin(target))
        if (target.factoryDefaultSsid) add(defaultCredentials())
    }.sortedBy { it.viability.rank }

    /**
     * The one-line answer: what an operator should actually do next.
     *
     * Deliberately never says a network is secure. It reports the cheapest route that is open and
     * what stands between the operator and the next one — absence of a route from this handset is
     * a statement about the handset.
     */
    fun verdict(target: Target): String {
        val routes = routesFor(target)
        val open = routes.filter { it.viability == Viability.OPEN }
        val nearest = routes.firstOrNull { it.viability != Viability.OPEN && it.viability.rank < Viability.BLOCKED.rank }

        return buildString {
            if (open.isNotEmpty()) {
                append("Reachable now: ")
                append(open.joinToString { it.name })
                append(". ")
            } else {
                append("No route is open from this handset as it stands. ")
            }
            nearest?.let {
                append("Next cheapest is ${it.name} — ${it.requires ?: it.rationale} ")
            }
            append(
                "Routes marked blocked are limits of this hardware, not of the target: a radio " +
                    "that does monitor mode and injection opens most of them.",
            )
        }
    }

    private fun openNetwork(target: Target) = when {
        target.isOpen -> Route(
            name = "Join directly",
            viability = Viability.OPEN,
            rationale = "The network is unencrypted, so association needs nothing at all. " +
                "Everything on it is readable by anyone in range, and a captive portal in front " +
                "of it is a web target rather than a link-layer control.",
            module = "t0.wifi.join",
        )

        else -> Route(
            name = "Join directly",
            viability = Viability.NOT_APPLICABLE,
            rationale = "The network is encrypted, so association needs a key.",
        )
    }

    private fun wpsPushButton(target: Target) = when {
        target.wpsPushButtonActive -> Route(
            name = "WPS push-button association",
            viability = Viability.OPEN,
            rationale = "The AP is advertising an active push-button session. Any station in " +
                "range can associate for its duration without the passphrase. This closes on its " +
                "own within about two minutes.",
            module = "t0.wifi.join",
        )

        else -> Route(
            name = "WPS push-button association",
            viability = Viability.NOT_APPLICABLE,
            rationale = "No push-button session is active. It would have to be triggered at the " +
                "AP, which is physical access rather than a remote route.",
        )
    }

    private fun wpsOverUpnp(target: Target): Route {
        if (!target.wpsAdvertised) {
            return Route(
                name = "WPS External Registrar over UPnP",
                viability = Viability.NOT_APPLICABLE,
                rationale = "The AP does not advertise WPS.",
            )
        }

        val lockNote = when (target.wpsPinLocked) {
            true -> "The beacon reports AP Setup Locked, which refuses PIN attempts over the " +
                "air — but that lock lives in the radio path and the UPnP registrar is a " +
                "different code path that commonly ignores it. Worth trying anyway."
            false -> "The beacon reports the PIN as unlocked, so attempts are being accepted."
            null -> "The beacon does not carry the lock state, so it has to be tested."
        }

        return Route(
            name = "WPS External Registrar over UPnP",
            viability = if (target.haveLanAccess) Viability.OPEN else Viability.NEEDS_ACCESS,
            rationale = "The registrar protocol is also exposed over UPnP/SOAP on most consumer " +
                "firmware, and that path is ordinary HTTP. Where it answers unauthenticated, the " +
                "exchange returns the AP's live configuration including the passphrase. $lockNote",
            requires = if (target.haveLanAccess) {
                null
            } else {
                "an IP on this network first — it is an IP-layer attack, so it is a pivot (guest " +
                    "segment to main passphrase, or a wired drop), not a way through the front door"
            },
            module = "t0.exploit.wpsregistrar",
        )
    }

    private fun offlineCrack(target: Target): Route {
        if (target.isSaeOnly) {
            return Route(
                name = "Offline passphrase recovery",
                viability = Viability.NOT_APPLICABLE,
                rationale = "The AP offers SAE only. WPA3's handshake is a password-authenticated " +
                    "key exchange, so a captured exchange cannot be tested against a wordlist " +
                    "offline — this is the specific thing SAE was designed to stop.",
            )
        }
        if (!target.hasPresharedKey) {
            return Route(
                name = "Offline passphrase recovery",
                viability = Viability.NOT_APPLICABLE,
                rationale = if (target.isEnterprise) {
                    "The network uses 802.1X, so there is no shared passphrase to recover. The " +
                        "equivalent target is the RADIUS exchange and the client's certificate " +
                        "validation."
                } else {
                    "No passphrase-derived key is in use."
                },
            )
        }

        val transitionNote = if (!target.isSaeOnly && target.hasPresharedKey) {
            " Where the AP runs WPA3 in transition mode it still accepts PSK, so SAE's protection " +
                "against exactly this is sidestepped by negotiating the older path."
        } else {
            ""
        }

        return Route(
            name = "Offline passphrase recovery",
            viability = if (target.haveCapture) Viability.OPEN else Viability.NEEDS_CAPTURE,
            rationale = "A captured four-way handshake carries the nonces, both addresses and a " +
                "MIC in the clear, which is everything needed to test a guess with no network " +
                "involved. Nothing rate-limits it, logs it, or can notice it happening.$transitionNote",
            requires = if (target.haveCapture) {
                null
            } else {
                "a handshake for this SSID, dropped into the handshakes folder as .22000 or " +
                    ".hccapx — collecting one needs an adapter that does monitor mode"
            },
            module = "t0.crack.handshake",
        )
    }

    private fun pmkid(target: Target): Route {
        if (target.isSaeOnly || !target.hasPresharedKey) {
            return Route(
                name = "PMKID recovery",
                viability = Viability.NOT_APPLICABLE,
                rationale = "A PMKID is derived from a passphrase-derived PMK, which this network " +
                    "does not use.",
            )
        }
        return Route(
            name = "PMKID recovery",
            viability = if (target.haveCapture) Viability.OPEN else Viability.NEEDS_CAPTURE,
            rationale = "The cheaper of the two offline targets: a PMKID comes out of the AP's own " +
                "first response to an association request, so it needs no legitimate client to have " +
                "been present and no waiting for someone to connect. Not every AP volunteers one.",
            requires = if (target.haveCapture) {
                null
            } else {
                "a PMKID for this SSID — hcxdumptool against the AP, converted with hcxpcapngtool"
            },
            module = "t0.crack.handshake",
        )
    }

    private fun wpsOverAir(target: Target) = when {
        !target.wpsAdvertised -> Route(
            name = "WPS PIN over the air",
            viability = Viability.NOT_APPLICABLE,
            rationale = "The AP does not advertise WPS.",
        )

        else -> Route(
            name = "WPS PIN over the air",
            viability = Viability.BLOCKED,
            rationale = "The PIN is validated in two independent halves, which reduces an " +
                "eight-digit secret to about eleven thousand guesses — but running it needs WPS " +
                "frames this handset cannot send. WifiManager.startWps was deprecated in API 26 " +
                "and removed in API 28, with no replacement, and the underlying exchange needs " +
                "injection.",
            requires = "an adapter with injection, driven from a host that has reaver or bully. " +
                "The UPnP route above reaches the same registrar without any of that.",
        )
    }

    private fun handshakeCapture(target: Target): Route {
        val pmfNote = if (target.managementFrameProtectionRequired) {
            " This AP requires 802.11w, so deauthentication will not work against it even with " +
                "capable hardware — a capture would have to wait for a client to associate on its own."
        } else {
            " This AP does not require 802.11w, so a client can be deauthenticated to force a " +
                "reconnection and produce a handshake on demand."
        }

        return Route(
            name = "Capture a handshake here",
            viability = Viability.BLOCKED,
            rationale = "Collecting a handshake means reading frames addressed to other stations, " +
                "which needs monitor mode. Android has never exposed it to an app at any patch " +
                "level, and it is a driver capability rather than a permission, so root alone " +
                "does not add it.$pmfNote",
            requires = "an external adapter whose driver supports monitor mode, which on Android " +
                "also needs a kernel carrying that driver",
        )
    }

    private fun evilTwin(target: Target) = Route(
        name = "Evil twin / karma",
        viability = Viability.BLOCKED,
        rationale = "Standing up a clone of '${target.ssid}' needs a SoftAP with a chosen SSID " +
            "and the ability to answer probe requests. The platform picks the hotspot SSID " +
            "itself and gives an app no control over it, so this is not reachable at any tier " +
            "on stock Android.",
        requires = "a host running hostapd against an adapter it controls",
    )

    private fun defaultCredentials() = Route(
        name = "Default administrative credentials",
        viability = Viability.NEEDS_ACCESS,
        rationale = "The SSID is still the factory one, which is strong evidence nobody opened " +
            "the admin interface — and that is where the shipped administrative password still " +
            "is. Getting the router's admin page reveals the passphrase directly.",
        requires = "an IP on this network, or on a guest segment that is not isolated from the " +
            "router's management interface",
        module = "t0.exploit.defaultcreds",
    )
}
