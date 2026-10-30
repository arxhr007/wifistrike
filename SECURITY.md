# Security Policy

WiFiStrike is a Wi-Fi deauthentication tool built with Scapy. It sends IEEE
802.11 management frames (deauthentication/disassociation) that can disrupt
connectivity for devices on a wireless network. Because of this, the project
treats "security" as covering both *how we handle vulnerabilities in the
code* and *how the tool itself must be used responsibly*. Read this document
before running WiFiStrike against any network.

## Table of Contents

- [Legal Notice](#legal-notice)
- [Authorized Testing Scenarios](#authorized-testing-scenarios)
- [Impact of Deauthentication Attacks](#impact-of-deauthentication-attacks)
- [Controlled Lab Testing](#controlled-lab-testing)
- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Supported Versions](#supported-versions)
- [Hardening Recommendations for Operators](#hardening-recommendations-for-operators)

## Legal Notice

Transmitting deauthentication or disassociation frames at a network you do
not own, and do not have **explicit, documented, written authorization** to
test, is illegal in most jurisdictions (e.g. under the U.S. Computer Fraud
and Abuse Act, the UK Computer Misuse Act, and equivalent laws elsewhere) and
may also violate radio-spectrum regulations (e.g. FCC Part 15 in the US)
because deauth frames are a form of intentional interference. It can also
violate the Terms of Service of ISPs, landlords, employers, and venues.

This repository is published for education, authorized penetration testing,
and defensive security research. The author and contributors accept **no
liability** for misuse. If you run WiFiStrike, you are personally and
solely responsible for ensuring your use is lawful and authorized.

## Authorized Testing Scenarios

Only run WiFiStrike in situations where authorization is unambiguous. Examples
of generally acceptable use:

1. **Your own home/personal lab network** — a network you own, administer,
   and are the only person affected by, running on hardware you control.
2. **Contracted penetration tests / red team engagements** — you have a
   signed statement of work or rules of engagement (RoE) naming the specific
   SSIDs/BSSIDs, time windows, and scope that authorize wireless attack
   simulation, issued by someone with the authority to grant it (not just
   any employee).
3. **Internal security assessments** — you are an employee or contractor of
   the network's owning organization, acting under a documented, signed
   authorization from IT/security leadership, within an approved maintenance
   window.
4. **Capture-the-flag (CTF) competitions and training ranges** — the
   infrastructure is explicitly built and provided for attack practice
   (e.g. dedicated CTF Wi-Fi ranges, vendor-provided hacking labs), and the
   competition rules permit deauthentication.
5. **Academic research with IRB/ethics approval** — research conducted on
   infrastructure you control, with ethics review and informed consent
   where human subjects or shared networks are involved.

Before testing, confirm in writing:

- Exact scope (SSIDs/BSSIDs/MAC ranges, physical locations, time windows).
- Who owns the network and who signed off.
- An emergency stop/contact procedure if something unexpected breaks (e.g.
  the deauth also affects a neighboring, out-of-scope network because Wi-Fi
  signals don't respect property lines).
- Logging/evidence requirements for the engagement report.

If you are not holding a document that answers all of the above, you do not
have authorization. Running WiFiStrike against a neighbor's network, a
public coffee shop, a corporate network without written sign-off, or "just
to see if it works" on someone else's Wi-Fi is unauthorized and out of scope
for this project's intended use.

## Impact of Deauthentication Attacks

Deauthentication works because, in unprotected 802.11 management frames
(pre-802.11w/Protected Management Frames), a client has no way to verify that
a `Deauth`/`Disassoc` frame genuinely came from its access point. An attacker
who can see traffic on the channel can forge these frames with the AP's or a
client's MAC address and force a disconnect. Understanding the real-world
impact matters for anyone deciding whether, when, and how narrowly to test:

- **Denial of service.** Targeted or broadcast deauth frames repeatedly
  disconnect one client or every client associated with an AP, preventing
  normal use of the network for as long as the attack runs.
- **Blast radius beyond the intended target.** 802.11 is broadcast over the
  air. A broadcast deauth (`-t 0` in this tool) affects *every* client on
  that BSSID, not just a chosen device, and signal can leak into adjacent
  rooms, floors, or buildings — including networks that were never in scope.
- **Safety and availability-critical impact.** Many devices now depend on
  Wi-Fi for safety or operational functions: VoIP/emergency calling, medical
  telemetry, point-of-sale terminals, security cameras/alarm panels, smart
  locks, industrial sensors. An "it's just Wi-Fi" disruption can have
  consequences well beyond annoyance.
- **Enabling follow-on attacks.** Deauth is frequently chained into other
  attacks: forcing a WPA/WPA2 4-way handshake capture for offline password
  cracking, forcing clients to roam onto an attacker-controlled evil-twin AP,
  or downgrading clients that will reconnect to open/rogue networks.
- **Detection and attribution.** Deauth floods are loud. Wireless intrusion
  detection systems (WIDS), many enterprise APs, and tools like Kismet or
  Wireshark readily flag abnormal deauth/disassoc rates, and the source MAC
  (even if spoofed) and physical signal can often be triangulated. Unauthorized
  use is likely to be detected and is legally traceable.
- **Legal/regulatory exposure.** Beyond computer-misuse statutes, deliberate
  RF jamming/interference with licensed or unlicensed spectrum carries its
  own regulatory penalties (e.g., FCC enforcement actions) independent of any
  "hacking" charge.
- **Mitigations that reduce (but don't eliminate) impact.** 802.11w
  (Protected Management Frames / PMF) cryptographically protects
  deauth/disassoc frames and makes this style of attack far less effective
  against clients and APs that enforce it; WPA3 mandates PMF. Part of the
  value of *authorized* deauth testing is verifying whether PMF is actually
  enforced on a given network.

## Controlled Lab Testing

To learn or validate WiFiStrike's behavior without touching any real,
in-use network, use an isolated lab setup:

### Recommended lab setup

1. **RF isolation.** Ideally use a Faraday bag/enclosure, RF-shielded room,
   or attenuated test chamber so transmissions can't reach real-world
   devices or networks outside your control. At minimum, run on a channel
   and in a physical location far from any production/neighboring Wi-Fi, and
   keep transmit power low.
2. **Your own dedicated AP.** Stand up a disposable access point you own —
   a spare router, a Raspberry Pi running `hostapd`, or a software AP — with
   an SSID that is clearly a test network (e.g. `LAB-TEST-ONLY`) and no
   production traffic on it.
3. **Your own client device(s).** Use a spare phone, laptop, or a second
   adapter you control as the "victim" client, so the only thing affected by
   the deauth is equipment you own.
4. **A monitor-mode-capable adapter for WiFiStrike.** See the README's
   [Supported Network Adapters](README.md#-supported-network-adapters) list.
5. **Packet capture for verification.** Run `tcpdump`/Wireshark on the lab AP
   or a third sniffing adapter so you can confirm, frame-by-frame, exactly
   what WiFiStrike is sending (reason codes, addressing, timing) rather than
   just trusting the console output.

### Suggested lab procedure

```bash
# 1. Bring up an isolated test AP (example using hostapd on a spare device)
#    with a clearly-labeled test SSID, on a channel/location away from
#    production networks.

# 2. Identify your lab adapter and put it in monitor mode
sudo wifistrike -l
sudo wifistrike --mon wlan1

# 3. Confirm you can see your OWN test AP and OWN test client
sudo wifistrike -sw -i wlan1
sudo wifistrike -st -i wlan1 -g <your-lab-ap-bssid>

# 4. Run a scoped, time-limited deauth against your OWN test client only
sudo wifistrike -i wlan1 -g <your-lab-ap-bssid> -t <your-lab-client-mac>

# 5. Capture and inspect what was actually sent
sudo tcpdump -i wlan1 -y DLT_IEEE802_11_RADIO -w lab-capture.pcap
#    then open lab-capture.pcap in Wireshark and filter: wlan.fc.type_subtype == 0x0c

# 6. Restore the adapter to managed mode when done
sudo wifistrike --man wlan1
```

### Software-only testing (no RF at all)

You do not need real radios or a live AP to validate the tool's *logic*
(frame construction, parsing, argument handling). This repository's
[`tests/`](tests/) directory builds and parses synthetic Scapy packets
in-process — no interface, root, or monitor mode required — and is the
preferred way to check changes before ever transmitting anything over the
air. See [Tests](#tests) below and [`tests/README.md`](tests/README.md).

Always treat RF-emitting tests as "loud": run them only on hardware and in
locations where you are certain no unintended network or device will be
affected.

## Reporting a Vulnerability

If you find a security issue in WiFiStrike itself (e.g. unsafe handling of
untrusted packet input, command injection, insecure installation/update
mechanism, privilege-escalation issues around the root-requiring code
paths), please report it responsibly:

- Open a [GitHub Security Advisory](https://github.com/arxhr007/wifistrike/security/advisories/new)
  (preferred — keeps the report private until a fix is ready), or
- Open a regular issue **without** proof-of-concept exploit details if a
  private advisory isn't available to you, and note that it's a security
  report so it can be triaged accordingly.

Please include:
- The affected version/commit.
- Steps to reproduce (ideally using the lab setup above, not a live network).
- Expected vs. actual behavior.
- Any relevant logs or `tcpdump`/Wireshark captures from a lab environment.

We aim to acknowledge reports within a few days. Please do not publicly
disclose details until a fix has been released.

**Do not use this project's issue tracker to request help attacking a
specific real-world network, or to report "it worked against my
neighbor/school/office Wi-Fi."** Such reports will be closed without
response and may be reported to GitHub as abuse under GitHub's
[Active Malware or Exploits policy](https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies#5-additional-product-terms-for-dual-use-content)
if they describe unauthorized use.

## Supported Versions

This project does not currently maintain multiple release branches. Security
fixes are applied to the latest version on `main`. There is no guaranteed
backport policy for older tags/commits — please use the latest `main`.

## Hardening Recommendations for Operators

If you administer a Wi-Fi network and want to reduce your exposure to
deauthentication-style attacks (from this tool or any other):

- **Enable 802.11w (Protected Management Frames)** on your APs, and prefer
  WPA3, which mandates PMF.
- **Deploy a Wireless Intrusion Detection/Prevention System (WIDS/WIPS)** to
  alert on abnormal deauth/disassoc frame rates.
- **Monitor for rogue APs and evil-twin SSIDs**, since deauth is frequently
  used to force clients toward them.
- **Segment and physically constrain RF** where possible (directional
  antennas, reduced transmit power, shielding) in sensitive environments.
- **Have an incident response plan** for sustained wireless DoS, including
  how to detect it is happening and who to escalate to.
