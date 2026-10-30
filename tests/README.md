# Tests

These are offline unit tests. They build and parse **simulated** 802.11
packets entirely in memory using Scapy, and exercise WiFiStrike's frame
construction and packet-parsing logic directly. None of them:

- open a real network interface,
- require root or monitor mode,
- call `sendp()`/`sniff()` against live hardware, or
- transmit or receive anything over the air.

This makes it safe to run them on any machine (including CI), and it's the
recommended way to validate changes before ever running WiFiStrike against
real radio hardware. See [`../SECURITY.md`](../SECURITY.md#controlled-lab-testing)
for how to move from here to controlled, RF-isolated lab testing with real
hardware once you need to validate on-air behavior.

## Running

```bash
pip install -r ../requirements.txt -r ../requirements-dev.txt
pytest
```

(from the repository root: `pytest` picks up this `tests/` directory
automatically.)

## What's covered

- **`test_deauth_frames.py`** — builds targeted and broadcast deauthentication
  frames with locally-administered, non-routable example MAC addresses
  (`02:00:00:00:00:01` / `02:00:00:00:00:02`, reserved by IEEE for
  documentation/testing use) and asserts the resulting frames have the
  correct addressing, layers, and reason codes. Also round-trips a frame
  through serialization to simulate what a receiver/capture would see.
- **`test_packet_parsing.py`** — builds synthetic beacon frames (simulating
  an access point) and data frames (simulating an associated client) and
  feeds them straight into `packet_handler` / `packet_handler1`, the same
  callbacks `sniff()` uses, to verify AP/client discovery logic without a
  live scan.

## Adding new tests

Prefer this pattern for anything that currently requires a live interface:
pull the packet-construction or packet-parsing logic into a small, pure
function (as was done for `build_deauth_frame`/`build_deauth_all_frame`),
then test that function with hand-built Scapy packets here. Keep anything
that actually calls `sendp()`/`sniff()`/touches `/dev` or a real interface
out of this directory — that belongs in manual, controlled lab testing per
[`SECURITY.md`](../SECURITY.md#controlled-lab-testing).
