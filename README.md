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
| **Tier 2 — Monitor** | Patched firmware (nexmon) or an OTG adapter with an `ath9k_htc` / `rtl8812au` driver | Monitor-mode verification and raw 802.11 capture |

The tier probe is not a version check. It asks for a root shell and reads the answer, walks
`/sys/class/net` for a second radio, and looks for patched-firmware markers — because a `su`
binary that denies every request is not root, and that difference matters before a module tries
to run tcpdump.

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
- `t0.wifi.survey` — enumerates nearby APs and grades each one's advertised security: encryption
  suite, WPS exposure, 802.11w management frame protection, hidden SSIDs.
- `t0.wifi.rogue` — correlates every BSSID broadcasting each SSID and flags security downgrades
  and vendor mismatches that suggest an evil twin. Detection, not impersonation.
- `t0.capture.vpn` — rootless traffic capture to pcap, as above. Run it again to stop.

**Tier 0 — active**
- `t0.net.discovery` — subnet sweep via ICMP echo plus TCP connect probes. Caps at a /22, because
  a /16 sweep is 65k probes and a flat battery.
- `t0.net.portscan` — connect-scans a well-known port set on the selected hosts, with banner
  grabbing. A full handshake lands in the target's logs; SYN scanning needs Tier 1.
- `t0.tls.audit` — negotiated protocol and cipher, certificate expiry, self-signed chains, SHA-1
  and MD5 signatures.

**Tier 1**
- `t1.capture.pcap` — tcpdump on a live interface. Managed mode, so this sees the device's own
  traffic plus broadcast and multicast — not other stations' unicast.

**Tier 2**
- `t2.radio.monitor` — verifies a radio really enters monitor mode and enumerates the channels
  the driver reports.

### Deliberately not implemented

Frame injection, and deauthentication in particular. A deauth flood is a denial-of-service
primitive against every station on the channel, not just the one under test. The rogue-AP module
detects impersonating infrastructure rather than standing any up.

## Building

Requires JDK 17+ and the Android SDK (compileSdk 35, build-tools 35.0.0). Point `sdk.dir` in
`local.properties` at your SDK, then:

```
gradle assembleDebug          # → app/build/outputs/apk/debug/app-debug.apk
gradle testDebugUnitTest      # 32 tests: packet codec, CIDR, target selection, AP analysis
```

`minSdk` is 26, `targetSdk` 35.

## Architecture

```
core/
  capability/   Tier, DeviceCapabilities, CapabilityProbe — what this device can actually do
  capture/      Packets, TcpRelay, UdpRelay, PcapWriter, CaptureVpnService — rootless capture
  net/          Cidr4 — IPv4 address arithmetic
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

- TLS interception on the capture path (local CA, per-flow MITM) for cleartext inspection
- Flow summary and protocol breakdown in-app, rather than exporting to Wireshark for everything
- IPv6 relay — the TUN is currently IPv4-only
- ICMP relay (needs a raw socket, so Tier 1)
- mDNS / SSDP / NBNS service enumeration
- BLE reconnaissance
- Captive portal and DNS-leak checks

## Authorised use

This is a tool for testing networks you own or have written permission to assess. Testing
networks without authorisation is illegal in most jurisdictions.
