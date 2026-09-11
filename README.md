# MobileOps

An Android toolkit for WiFi and network security assessment, built around one principle: **never
claim a capability the hardware will not actually give up.**

Status: early alpha, builds and runs. The Tier 0 module set is implemented, including rootless
packet capture; Tier 1 and Tier 2 modules are implemented but only testable on devices that meet
their requirements.

## The constraint everything is built around

Since Android 10, the platform will not put the internal WiFi chipset into monitor mode for an
app. No monitor mode means no raw 802.11 frame capture, no handshake capture, no injection —
regardless of how the app is written. Tools that claim otherwise on a stock phone are either
wrong or quietly doing nothing.

So MobileOps sorts every capability into tiers, probes the device at launch, and shows you an
honest picture of what this handset can do *before* you rely on it in the field.

| Tier | Requires | Capabilities |
| --- | --- | --- |
| **Tier 0 — Stock** | Nothing | AP survey and security grading, rogue-AP correlation, subnet discovery, TCP service scanning, TLS/certificate audit, **full traffic capture to pcap** |
| **Tier 1 — Root** | A working `su` | tcpdump on a live interface, raw sockets, firewall manipulation, bundled binaries |
| **Tier 2 — Monitor** | A kernel carrying the adapter's driver, plus root — see below | Monitor-mode verification and raw 802.11 capture |

The tier probe is not a version check. It asks for a root shell and reads the answer, walks
`/sys/class/net` for a second radio, and looks for patched-firmware markers — because a `su`
binary that denies every request is not root, and that difference matters before a module tries
to run tcpdump.

## External USB adapters

An Alfa or similar USB adapter is the standard route to monitor mode, and the app detects one on
the bus whether or not the kernel has claimed it. That distinction matters: an adapter with no
driver is invisible in `/sys/class/net` and looks identical to no adapter at all, while the fix
is completely different.

Recognised chipsets include AR9271 and AR7010 (`ath9k_htc`), RTL8187, RTL8812AU and RTL8811CU,
RT3070/RT5370 (`rt2800usb`), and MT7610U/MT7612U. An unlisted adapter is reported as unknown
rather than guessed at.

Plugging one in is the easy part. Using it needs, in order:

1. **A kernel containing the driver.** Stock Android kernels do not ship `ath9k_htc` or any of
   the others. In practice this means a custom or NetHunter kernel for the specific device — the
   single hardest requirement, and the one no app can work around.
2. **Firmware**, for chipsets that load it — `htc_9271.fw` for AR9271 — placed under
   `/lib/firmware`, which needs root.
3. **Root**, to load a module, place firmware, and reconfigure the interface.
4. **Enough power over OTG.** These adapters draw around 500 mA; a powered OTG hub avoids a
   brownout that presents as random disconnects.

The Device tab lists what is detected and what each adapter is still missing.

## Raw beacon elements

Android summarises an AP's security into a string like `[WPA2-PSK-CCMP][WPS]`, which is enough to
say WPS is enabled and nothing more. Since API 30 the elements underneath are readable without
root, and they carry what actually decides whether a weakness is exploitable:

- **WPS AP Setup Locked** — an unlocked PIN is an attack path; a locked one is a note. This single
  bit is the difference, and the capability string never carries it.
- **The real AKM and cipher lists** — SAE and PSK together is a confirmed downgrade path, not an
  inference from a summary string.
- **802.11w required vs merely capable** — an AP that supports management frame protection without
  insisting on it leaves any client that declines fully exposed.
- **Manufacturer, model and serial** from the WPS element — enough to look up firmware-specific
  vulnerabilities before touching the network.
- Whether an AP is still in its unconfigured out-of-box state.

## Rootless packet capture

The single most useful thing a stock Android device can do, and it needs no root at all.

`VpnService` hands any app that holds `BIND_VPN_SERVICE` a TUN interface with the system route
table pointed at it. MobileOps is not tunnelling anywhere — it reads each packet off the TUN,
writes it to a pcap, and forwards it onward itself through sockets excluded from the VPN route.

That forwarding is why `core/capture/` contains a userspace TCP implementation. The device's own
TCP stack believes it is talking to the real server; in fact it is talking to us, and we hold a
separate real socket to that server and shuttle bytes between the two. Getting that indirection
right is the whole cost of rootless capture:

- `Packets` — IPv4/TCP/UDP parsing and construction, including the pseudo-header checksums a
  receiving stack will verify.
- `TcpRelay` — per-flow userspace TCP: handshake, sequence and acknowledgement bookkeeping,
  ordered relay in both directions, FIN/RST teardown. No retransmission or congestion control,
  because the client side is a TUN where nothing is ever dropped, and loss on the real network is
  handled by the kernel on the far socket.
- `UdpRelay` — per-flow sockets with idle reaping.
- `PcapWriter` — classic libpcap, link type RAW (101), flushed per packet so a capture killed by
  the system is still readable.

Output opens directly in Wireshark. It sees **this device's traffic in full**; it does not see
other stations' traffic, which needs monitor mode.

## Device identity

Identity profiles (Device tab) present this handset as something else to the network under test —
a Windows laptop, a MacBook, a network printer, a fully random locally-administered address. The
purpose is testing identity-based controls: MAC allow-lists, NAC device profiling, and the
"printers are exempt" rule that so often turns out to be the way in.

Be clear about where the line falls, because Android has spent several releases closing exactly
these holes:

| | Stock | Root |
| --- | --- | --- |
| Read own WiFi MAC | No — the platform returns the constant `02:00:00:00:00:00` | Yes |
| Change WiFi MAC | No | Yes, `ip link` (some drivers still refuse) |
| Change DHCP hostname | No | Yes |
| Change outbound TTL | No | Yes, where the kernel's iptables has a TTL target |

So on a stock phone the profile picker is an audit reference, not a disguise — `t0.identity.audit`
reports what you are leaking and what a profile *would* change. Applying it is Tier 1.

Worth knowing regardless of tier: Android 10+ already randomises the MAC per saved network, so the
address on the air is not the hardware address. It is stable per SSID, so it still correlates
across sessions on the same network. And the device name goes out as the DHCP hostname, which
lands in the lease table no matter what the MAC says — that is the identifier people forget.

## TLS interception

Turns the encrypted half of a capture into readable requests. A local CA is generated on the
device, interception mints a certificate per hostname from the SNI in the ClientHello, and the
plaintext is relayed between two TLS connections — one to the device, one to the real server.

The device only accepts the substituted certificate if it trusts that CA, which is TLS working
as designed rather than a limitation to route around. What that means in practice:

| | Sees |
| --- | --- |
| CA not installed | Nothing. Every handshake is refused. |
| CA installed as a **user** certificate | Browsers, and apps that opt into user CAs |
| CA installed in the **system** store (root) | Everything except apps that pin |
| Certificate-pinning apps | Nothing, at any tier, by design |

Installing the CA is one tap: the interception card hands the certificate straight to the system
installer via `KeyChain.createInstallIntent()`. Some Android releases route CA installation
through Settings regardless, in which case the app says so and opens the right screen rather than
failing quietly.

It installs once. The CA is generated on first use and persisted, so the same certificate is
reused for the life of the install, and the card reads the device trust store to see where it
stands — `Install CA`, `CA installed ✓` (disabled), or `Clean up N CA copies` when entries from an
earlier CA are still present. Trust is matched on the certificate bytes, not its name, so a
regenerated CA is correctly reported as untrusted rather than mistaken for the one already there.
An app cannot delete a user-installed CA, so the cleanup path opens Settings rather than
pretending otherwise.

The middle row is the one that surprises people: since Android 7, apps trust user-installed CAs
only if their network security config opts in, and almost none do. So a user-installed CA is a
browser-traffic tool. `t0.tls.intercept` reports the exact filename the system store keys on
(`<subject hash>.0`) for the rooted case.

The upstream leg verifies the real server properly, hostname included — an `SSLSocket` does not
do that by default, and skipping it would hide a genuine attack on the path behind the
interception being performed.

Requests are logged with their method, host, path and any credential material **described but
never recorded**: bearer tokens, Basic auth, session cookies, `X-Api-Key`-style headers, and
credentials passed in query strings. An evidence file containing live credentials is its own
incident.

## Off the network

Not every module needs to be on the network under test, which makes the app useful while
walking around or on cellular:

| Works anywhere | Needs a local subnet |
| --- | --- |
| **RF site survey** — every AP in range, vendors, channel congestion, security census | Host discovery |
| **Network name intelligence** — factory SSIDs, ISP equipment, device types, personal names | Service & name discovery |
| **Geolocated survey** — coverage mapped to GPS, exported as WiGLE CSV | Port scan, TLS audit |
| **WPS default PIN derivation** — the sticker PIN computed from the BSSID | Web exposure, credentials |
| **BLE reconnaissance** — every advertising device in range, named and attributed | WPS registrar attack |
| **Classic Bluetooth discovery** — discoverable devices and what they are | |
| **Cellular survey** — operators, generations, serving-cell baseline, 2G exposure | |
| WiFi survey and beacon elements — scanning does not require associating | |
| Rogue AP correlation | |
| Device identity audit | |
| Traffic capture and TLS interception — these work fine over cellular | |

`t0.wifi.sitesurvey` is the module built for this. It repeats the scan four times — matching the
platform's per-window allowance rather than fighting it — and aggregates everything heard: vendor
from the BSSID prefix, 2.4 GHz channel overlap, a security census, and signal range per AP across
the sweep. APs worth a second look (open, WEP, WPS, or a randomised BSSID, which infrastructure
never has) get their own finding; the rest stay in the census so the report stays readable.

Where it stops being a survey and starts being reconnaissance is the analysis stacked on top.
`t0.wifi.ssidintel` reads the names for unchanged factory SSIDs and the vendor behind each,
`t0.wifi.survey` computes the likely default WPS PIN from every WPS-advertising BSSID, and
`t0.wifi.wardrive` attaches coordinates so the whole thing becomes a coverage map rather than a
list. All of it happens before there is any route to the network — so by the time there is one,
the candidate PINs are already computed and the registrar attack is a handful of attempts.

Beyond WiFi, the other radios answer without a network too: `t0.ble.recon` and `t0.bt.classic`
inventory what is physically present over Bluetooth, and `t0.cell.survey` works where there is no
wireless network at all.

### A note on what Android reports as WEP

The platform builds its capability string from the beacon, and emits `[WEP]` for any AP that sets
the privacy bit without an RSN or WPA element — which is what WEP meant in 2003. It is rarely
what it means now. WEP was struck from 802.11 in 2012 and cannot be used with HT, VHT or HE data
rates at all, so a 5 GHz 802.11ac radio advertising it is a contradiction; what it actually
indicates is a link running something other than 802.11i, usually a mesh backhaul or a Wi-Fi
Direct group owner. The analyser checks the beacon's own rate elements and reports those as
`Privacy set, no RSN` rather than raising a critical finding on a network nobody can join.

A carrier link hands out a /32, which is point-to-point: no neighbours, nothing to sweep. The LAN
modules detect that and say so rather than reporting a subnet that does not exist.

## Joining a target network

Survey works from outside; the LAN modules need to be on the network. `t0.wifi.join` bridges the
two using a per-app association, so the handset keeps whatever connection it had and only this
app's sockets move to the target. That matters when the phone must stay on cellular, or when
testing a guest network without giving up the operator's own connection.

The passphrase is entered on the Targets tab when exactly one network is selected, held in memory
for the association, and never written to the evidence log. An open network needs none. The
association is dropped by running the module again, and does not survive the app exiting.

Getting on is itself a result: it establishes that those credentials — or none at all — are
enough to reach the network.

## Targets

Modules that act on a host take their targets from the Targets tab: pick a WiFi network from a
live scan, a host that a subnet sweep turned up, or type one in. Discovered hosts are read back
out of the evidence log rather than tracked separately, so there is one source of truth for what
was seen.

Every module declares itself `PASSIVE` (reads frames already being broadcast) or `ACTIVE` (puts
packets on the wire addressed at a target), and the card says which before you run it.

Everything a module observes is filed into an append-only evidence log (JSONL, so a run killed
halfway still parses up to the last complete record) and exports as a Markdown report.

## Modules

The module list is grouped into collapsible sections, ordered the way an engagement actually runs
— survey the air, map the network, look at traffic, then test what was found. Each heading says
how many of its modules can run on this device, so a section that is entirely tier-locked can be
seen as such without opening it. Tier-gated modules sit together at the end rather than being
scattered among usable ones.


**Tier 0 — passive**
- `t0.wifi.assess` — **the module an engagement runs.** Takes the selected network, gathers
  everything passively observable about it, and reports how it would be entered: every route
  ranked by how close it is to working, each with what it needs and what is blocking it. Scoped
  to a selected target, because a survey that generates attack material for every AP in earshot
  produces a report about other people's networks.
- `t0.wifi.sitesurvey` — repeated sweep of the whole RF environment: every AP in range, vendors,
  channel congestion, security census. Needs no network of any kind.
- `t0.wifi.ssidintel` — reads every network name in range for what it gives away: unchanged
  factory SSIDs and the vendor behind them, ISP-supplied equipment, device types, disclosed
  network roles, personal names. Pure offline analysis.
- `t0.wifi.wardrive` — logs every AP heard against GPS position over a rolling sweep and writes a
  WiGLE-format CSV. Walk a perimeter with it running to map where a network is audible from
  outside the building.
- `t0.ble.recon` — enumerates BLE devices in range: names, vendors, item trackers, advertised
  services. Entirely passive, needs no network, reveals what is physically present.
- `t0.cell.survey` — enumerates every cellular cell the modem can hear: operators, generations,
  identifiers and signal. Records the serving cell as a baseline, and flags a live 2G carrier,
  which does not authenticate the network to the handset. Needs no WiFi and no data session.
- `t0.wifi.join` — associates this app with a selected network without changing the phone's own
  connection, so the LAN modules can run against it. Run again to disconnect.
- `t0.wifi.survey` — grades each AP's advertised security: encryption suite, WPS exposure,
  802.11w management frame protection, hidden SSIDs. Audits the selected networks, or everything
  in range when nothing is selected.
- `t0.wifi.rogue` — correlates every BSSID broadcasting each SSID and flags security downgrades
  and vendor mismatches that suggest an evil twin. Detection, not impersonation. Selecting a
  network narrows which *names* are correlated, never which radios — an evil twin is by
  definition a BSSID you did not select.
- `t0.identity.audit` — reports what the network can learn about this handset: DHCP hostname,
  MAC randomisation behaviour, and what the platform will not let an app read or change.
- `t0.capture.vpn` — rootless traffic capture to pcap, as above. Run it again to stop.
- `t0.tls.intercept` — arms TLS interception and manages the local CA. Run again to disarm.

**Tier 0 — active**
- `t0.bt.classic` — inquiry scan for discoverable classic Bluetooth devices, decoding the Class
  of Device into what each one is and which services it carries. Finds the laptops, printers and
  car kits BLE scanning cannot see. A device answering here has been left discoverable, which is
  the finding.
- `t0.net.services` — resolves names and services over NetBIOS, mDNS and SSDP: the announcements
  devices already make. Fills in the names reverse DNS cannot.
- `t0.net.discovery` — subnet sweep via ICMP echo plus TCP connect probes. Caps at a /22, because
  a /16 sweep is 65k probes and a flat battery.
- `t0.net.portscan` — connect-scans a well-known port set on the selected hosts, with banner
  grabbing. A full handshake lands in the target's logs; SYN scanning needs Tier 1.
- `t0.iot.discovery` — identifies **equipment** rather than ports: DICOM, HL7, BACnet, Modbus,
  MQTT, CoAP, RTSP, Niagara Fox, EtherNet/IP and the rest a top-1000 list misses. Speaks each
  protocol well enough to make the device identify itself, then says what it is and why it
  matters. Backs off automatically on fragile devices.
- `t0.tls.audit` — negotiated protocol and cipher, certificate expiry, self-signed chains, SHA-1
  and MD5 signatures.
- `t0.exploit.webexposure` — unauthenticated admin pages, directory listings, exposed config and
  version control, version-disclosing banners, missing security headers. GET requests only.
- `t0.exploit.defaultcreds` — tests vendor default credentials against HTTP Basic auth. Stops at
  the first pair that works.
- `t0.crack.handshake` — recovers a WPA2 passphrase offline from a captured four-way handshake
  or PMKID, and hands it to the join module. Needs no network; the capture has to come from an
  adapter that does monitor mode.
- `t0.exploit.wpsregistrar` — attacks the WPS External Registrar over UPnP. Tries unauthenticated
  settings retrieval, then the full M1-M8 registrar exchange with PINs derived from the AP's own
  MAC address, then finishes a half-recovered PIN. Recovers the WPA passphrase where it works.
  The one WPS attack surface reachable without monitor mode.

**Tier 1**
- `t1.capture.pcap` — tcpdump on a live interface. Managed mode, so this sees the device's own
  traffic plus broadcast and multicast — not other stations' unicast.
- `t1.identity.spoof` — applies the selected identity profile: WiFi MAC, DHCP hostname and
  outbound TTL.

**Tier 2**
- `t2.radio.monitor` — verifies a radio really enters monitor mode and enumerates the channels
  the driver reports.

## IoT and OT

On most sites the general-purpose scan *is* the assessment. On a site whose value is in its
devices — a hospital, a plant, a warehouse, a building with a serious BMS — it is the least
interesting part, because the equipment does not speak SSH or HTTP. It speaks DICOM, BACnet,
Modbus, HL7, MQTT, and a top-1000 port list contains none of them.

`t0.iot.discovery` scans the catalogue those protocols live in and speaks each one well enough
to make the device identify itself:

| Protocol | Probe | What it establishes |
| --- | --- | --- |
| DICOM | A-ASSOCIATE-RQ (C-ECHO) | Whether an imaging node accepts an association from an AE title it has never seen — DICOM's default access control is a name the *caller* chooses |
| HL7 MLLP | Port presence | A clinical interface carrying admissions, orders and results in cleartext with no transport authentication |
| BACnet | Who-Is | Building automation answering unauthenticated discovery. Base BACnet has no authentication at all |
| Modbus | Read Device Identification | Vendor, product and revision from a protocol with no authentication in it |
| MQTT | CONNECT with no credentials | Whether the broker accepts anonymous clients, which means subscribing to `#` returns the whole estate |
| CoAP | `GET /.well-known/core` | The device's complete resource map |
| RTSP | OPTIONS | Whether a camera stream is readable without credentials |

Then it classifies the host — imaging node, chiller controller, camera, interface engine — and
reports what the thing *is*, not which ports answered.

### Why it is deliberately slow

A great deal of operational and medical equipment runs a TCP stack written for a network where
nobody was rude, and will fault, reboot or stop answering under a scan a server would not
notice. In a clinical setting that is not a finding, it is a patient safety event.

So every port in the catalogue carries a fragility rating, and the moment anything on a host
looks like equipment the scanner drops to one connection at a time, stops grabbing banners, and
speaks only the read-defined exchange each protocol specifies. Findings on such a host also
carry an explicit warning not to point a general-purpose scanner at it.

**Every probe is read-only, and the encoders cannot express a write.** Modbus will set a coil for
anyone who asks, BACnet will write a setpoint, DICOM will accept a study. Where those control a
chiller, a room's pressure differential or an infusion, a write issued to see what happens is not
a test result — so there is no write path in the file to reach for under time pressure.

## Exploitation

Recon establishes that something is reachable; exploitation establishes that it matters. The
exploit modules are scoped to what proves a finding and stops:

- **Default credentials** are tested against HTTP Basic auth with about two dozen vendor pairs,
  spaced out, stopping at the first that works. That is enough to prove the device still has its
  shipped credentials. It is deliberately not a password cracker — long lists against small
  appliances trip lockouts and take devices off the network, which is a denial of service rather
  than a test result. Form logins are detected and reported rather than driven, because every
  vendor's form differs and submitting guesses blind risks locking the account.
- **Web exposure** is read-only: every request is a GET, so nothing changes state on the target.
  What is reachable is the whole proof.
- **WPS** is taken all the way to the passphrase. `t0.wifi.survey` computes the likely default
  PINs from a BSSID off-network — a long line of firmware generated the sticker PIN from the MAC
  with a published function — and `t0.exploit.wpsregistrar` tests them by running the registrar
  protocol over UPnP. The protocol validates each half of the PIN separately and says which one
  failed, so a candidate that fails at M6 rather than M4 has already given up the first four
  digits, leaving a thousand-guess remainder that the module finishes in the same run. Where the
  exchange completes, M7 carries the AP's live configuration and the network key comes back in
  clear.

  The exchange is deliberately aborted with a NACK after M7. A real M8 pushes *new* settings onto
  the AP, so completing the protocol properly would reconfigure the network under test; aborting
  leaves it exactly as it was found.

These stop at demonstration. None pivots, persists, or modifies the target.

## Attack paths

A list of weaknesses is not a WiFi assessment. "WPS is enabled" and "802.11w is optional" are
true statements that do not tell an operator whether they are getting onto the network this
afternoon or not at all. What decides that is which routes are open, what each one needs that
the operator may not have, and which is cheapest.

`t0.wifi.assess` answers that for one selected network. Every route it knows about is reported
with a viability:

| Viability | Meaning |
| --- | --- |
| **Open now** | Usable from this handset with what is already known. |
| **Needs LAN access first** | Usable once the phone has an IP on the network — a pivot, not an entry. |
| **Needs a capture** | Usable once a handshake or PMKID is supplied from hardware that can collect one. |
| **Blocked on this device** | Not reachable from a stock handset, with the reason and the hardware that would change it. |
| **Not applicable** | The target's own configuration closes it. |

Blocked routes are reported rather than hidden. Most published WiFi attacks need monitor mode or
injection, and a tool that lists those as available is lying to its operator — whereas saying
*why* they are blocked tells them exactly what hardware changes the answer.

Two judgements in there are worth stating outright, because getting either wrong sends an
operator after something that cannot work:

- **SAE-only defeats offline recovery.** WPA3's handshake is a password-authenticated key
  exchange, so a captured exchange cannot be tested against a wordlist. This is the specific
  thing SAE was designed to stop. **Transition mode is different** — it still accepts PSK, so
  it remains a passphrase target, and that is the whole point of flagging transition mode.
- **802.11w decides whether a capture can be forced.** Where PMF is required, deauthentication
  does not work even with capable hardware, so a handshake has to be waited for rather than
  provoked.

The verdict never says a network is secure. Absence of a route from this handset is a statement
about the handset.

### Getting onto a network you do not have the key for

`t0.wifi.join` authenticates — it needs the passphrase. These are the routes that do not, and
the list is short on purpose because most of them are closed on a stock handset:

| Route | Status on a stock Pixel |
| --- | --- |
| WPS PIN over the air | **Closed.** `WifiManager.startWps()` was deprecated in API 26 and removed in API 28. There is no replacement API, and the frames it used to send need injection. |
| WPS registrar over UPnP | **Open, but post-access.** It is an IP-layer attack, so it needs a route to the AP already — useful for pivoting off a guest network to the main passphrase, not for the first step. |
| Offline handshake or PMKID cracking | **Open**, and the one that actually works. The capture has to come from hardware that does monitor mode; the phone does the search. |
| Online WPA2 guessing | **Closed.** `WifiNetworkSpecifier` raises a system dialog per attempt, and network suggestions are auto-join hints the platform schedules rather than a way to test keys at any useful rate. |
| WEP | Crackable in principle, but capturing the traffic needs monitor mode, and nothing modern actually runs it. |
| Open network with a captive portal | Joinable outright; the portal is then a web target like any other. |

So the realistic chain is: survey off-network to pick the target and derive its likely WPS PIN →
capture a handshake or PMKID with an adapter that can → crack it on the phone with
`t0.crack.handshake` → the recovered key is handed straight to `t0.wifi.join`.

`t0.crack.handshake` reads `.22000` and `.hccapx` files from
`Android/data/dev.cyphernova.mobileops/files/handshakes/`, and a wordlist from the `wordlists/`
folder beside it — both reachable from a file manager with no storage permission. `hcxpcapngtool`
converts a pcapng to `.22000`. Candidates are ordered cheapest-first: names derived from the SSID,
then the router-label shapes, then the wordlist, because a phone manages a few thousand PBKDF2
derivations a second and ordering is most of what makes that useful.

It requires a selected target. A capture file usually holds handshakes for every AP that was
audible when it was taken, and only the one under test should be attacked.

A failed run means the passphrase was not in the candidates tried. It does not mean the network
is secure — the same capture can be worked indefinitely, on faster hardware, against a larger
list, with nothing on the network able to notice.

### WiFi attacks and what a phone can reach

Every classic WiFi attack needs to transmit or receive raw 802.11 frames, which means monitor
mode and injection — Tier 2, and unreachable on a stock handset at any tier below it:

| Attack | Needs | On a stock phone |
| --- | --- | --- |
| Deauthentication | Injection | No |
| WPA handshake capture | Monitor mode | No |
| PMKID capture | Injection | No |
| WPS PIN / Pixie Dust over the air | Injection | No — but see WPS over UPnP below |
| Online WPA2 passphrase guessing | Silent association attempts | No — `WifiNetworkSpecifier` raises a system dialog per attempt |
| Evil twin / karma | SoftAP with a chosen SSID | No — the platform picks the SSID |

The exception is **WPS over UPnP**. The Wi-Fi Alliance defined the External Registrar protocol
over UPnP/SOAP as well as over 802.11, and consumer routers enable it on the LAN by default. That
path is ordinary HTTP, so `t0.exploit.wpsregistrar` reaches it from an unrooted phone — and it
sits on a different code path from the radio-side PIN lock, so an AP refusing PIN attempts over
the air can still answer here.

Offline work is also unconstrained by the radio: a handshake or PMKID captured on other hardware
can be cracked on the phone, since that is compute rather than RF.

### Deliberately not implemented

Frame injection, and deauthentication in particular. A deauth flood is a denial-of-service
primitive against every station on the channel, not just the one under test. The rogue-AP module
detects impersonating infrastructure rather than standing any up.

## Building

Requires JDK 17+ and the Android SDK (compileSdk 35, build-tools 35.0.0). Point `sdk.dir` in
`local.properties` at your SDK, then:

```
gradle assembleDebug          # → app/build/outputs/apk/debug/app-debug.apk
gradle testDebugUnitTest      # 134 tests: packet codec, beacon IEs, TLS/SNI, CA, UPnP/WPS
```

`minSdk` is 26, `targetSdk` 35.

## Architecture

```
core/
  capability/   Tier, DeviceCapabilities, CapabilityProbe — what this device can actually do
  capture/      Packets, TcpRelay, UdpRelay, PcapWriter, CaptureVpnService — rootless capture
  beacon/       BeaconElements — raw 802.11 information elements
  discovery/    Nbns, Mdns, Ssdp — name and service announcement codecs
  identity/     DeviceProfile, IdentityProbe — what this device presents to a network
  net/          Cidr4 — IPv4 address arithmetic
  tls/          CertificateAuthority, SniParser, MitmServer, HttpPeek — interception
  target/       Target, TargetSelection — what modules are pointed at
  module/       PentestModule, ModuleRunner, ModuleRegistry — the single door every run goes through
  evidence/     Finding, EvidenceStore — append-only log and Markdown report
modules/
  tier0/ tier1/ tier2/
ui/             Compose: device, targets, modules, evidence
```

`ModuleRunner` is the only path to running a module. It checks tier, runtime permissions and
target selection before anything touches the network, and files whatever the module emits
directly into the evidence store, so a run always leaves a record.

The packet codec, CIDR maths, target selection and AP analyser carry no Android dependencies, so
they unit-test on the JVM without an emulator. The checksum tests verify the property a receiving
stack actually checks — that summing a segment including its checksum field yields `0xFFFF` —
which is the same question as "would the far end accept this packet".

## Roadmap

Ordered for an unrooted device, since that is the target:

- Flow summary and protocol breakdown in-app, rather than exporting to Wireshark for everything
- IPv6 relay — the TUN is currently IPv4-only
- HTTP security-header auditing on intercepted flows
- Captive portal and DNS-leak checks
- BLE reconnaissance
- ICMP relay (needs a raw socket, so Tier 1)

## Authorised use

This is a tool for testing networks you own or have written permission to assess. Testing
networks without authorisation is illegal in most jurisdictions.
