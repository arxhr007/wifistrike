"""Tests for deauthentication frame construction, using simulated packet data.

These tests only build Scapy packet objects in memory and inspect their
fields; they never call ``sendp`` / ``sniff`` and never touch a real network
interface.
"""
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap

LAB_GATEWAY_MAC = "02:00:00:00:00:01"  # locally-administered, non-routable test MAC
LAB_CLIENT_MAC = "02:00:00:00:00:02"   # locally-administered, non-routable test MAC
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def test_build_deauth_frame_targets_correct_addresses(ws):
    frame = ws.build_deauth_frame(LAB_CLIENT_MAC, LAB_GATEWAY_MAC)

    dot11 = frame.getlayer(Dot11)
    assert dot11 is not None
    # addr1 = destination (the client being kicked), addr2/addr3 = BSSID (AP)
    assert dot11.addr1 == LAB_CLIENT_MAC
    assert dot11.addr2 == LAB_GATEWAY_MAC
    assert dot11.addr3 == LAB_GATEWAY_MAC


def test_build_deauth_frame_has_radiotap_and_deauth_layers(ws):
    frame = ws.build_deauth_frame(LAB_CLIENT_MAC, LAB_GATEWAY_MAC)

    assert frame.haslayer(RadioTap)
    assert frame.haslayer(Dot11Deauth)
    assert frame[Dot11Deauth].reason == 7  # default: class 3 frame received from nonassociated station


def test_build_deauth_frame_reason_code_is_configurable(ws):
    frame = ws.build_deauth_frame(LAB_CLIENT_MAC, LAB_GATEWAY_MAC, reason=1)
    assert frame[Dot11Deauth].reason == 1


def test_build_deauth_all_frame_is_broadcast(ws):
    frame = ws.build_deauth_all_frame(LAB_GATEWAY_MAC)

    dot11 = frame.getlayer(Dot11)
    assert dot11.addr1 == BROADCAST_MAC
    assert dot11.addr2 == LAB_GATEWAY_MAC
    assert dot11.addr3 == LAB_GATEWAY_MAC
    assert frame.haslayer(Dot11Deauth)


def test_deauth_frame_round_trips_through_serialization(ws):
    """Frames should survive a build -> bytes -> parse round trip.

    This simulates what a receiver (or a capture file) would see, without
    ever putting bytes on the air.
    """
    frame = ws.build_deauth_frame(LAB_CLIENT_MAC, LAB_GATEWAY_MAC)
    raw = bytes(frame)

    parsed = RadioTap(raw)
    assert parsed.haslayer(Dot11Deauth)
    assert parsed[Dot11].addr1 == LAB_CLIENT_MAC
    assert parsed[Dot11].addr2 == LAB_GATEWAY_MAC
