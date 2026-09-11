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

**Tier 0 — passive**
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
- `t0.net.services` — resolves names and services over NetBIOS, mDNS and SSDP: the announcements
  devices already make. Fills in the names reverse DNS cannot.
- `t0.net.discovery` — subnet sweep via ICMP echo plus TCP connect probes. Caps at a /22, because
  a /16 sweep is 65k probes and a flat battery.
- `t0.net.portscan` — connect-scans a well-known port set on the selected hosts, with banner
  grabbing. A full handshake lands in the target's logs; SYN scanning needs Tier 1.
- `t0.tls.audit` — negotiated protocol and cipher, certificate expiry, self-signed chains, SHA-1
  and MD5 signatures.
- `t0.exploit.webexposure` — unauthenticated admin pages, directory listings, exposed config and
  version control, version-disclosing banners, missing security headers. GET requests only.
- `t0.exploit.defaultcreds` — tests vendor default credentials against HTTP Basic auth. Stops at
  the first pair that works.
- `t0.exploit.wpsregistrar` — tests whether the WPS External Registrar answers unauthenticated
  over UPnP. The one WPS attack surface reachable without monitor mode.

**Tier 1**
- `t1.capture.pcap` — tcpdump on a live interface. Managed mode, so this sees the device's own
  traffic plus broadcast and multicast — not other stations' unicast.
- `t1.identity.spoof` — applies the selected identity profile: WiFi MAC, DHCP hostname and
  outbound TTL.

**Tier 2**
- `t2.radio.monitor` — verifies a radio really enters monitor mode and enumerates the channels
  the driver reports.

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

Both stop at demonstration. Neither pivots, persists, or modifies the target.

### WiFi attacks and what a phone can reach

Every classic WiFi attack needs to transmit or receive raw 802.11 frames, which means monitor
mode and injection — Tier 2, and unreachable on a stock handset at any tier below it:

| Attack | Needs | On a stock phone |
| --- | --- | --- |
| Deauthentication | Injection | No |
| WPA handshake capture | Monitor mode | No |
| PMKID capture | Injection | No |
| WPS PIN / Pixie Dust over the air | Injection | No |
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
