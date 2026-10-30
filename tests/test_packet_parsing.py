"""Tests for AP/client discovery parsing, using simulated packet data.

Simulated beacon and data frames are built in-memory with Scapy and fed
directly into the module's packet-handling callbacks, exactly as ``sniff``
would -- but with no interface, no root, and no real radio traffic involved.
"""
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap

LAB_AP_BSSID = "02:00:00:00:00:01"
LAB_CLIENT_MAC = "02:00:00:00:00:02"
LAB_SSID = "LAB-TEST-ONLY"


def _make_beacon(bssid=LAB_AP_BSSID, ssid=LAB_SSID, channel=6):
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid.encode(), len=len(ssid))
    ds_set = Dot11Elt(ID="DSset", info=bytes([channel]))
    rsn = Dot11Elt(ID=48, info=(
        b"\x01\x00"          # RSN version
        b"\x00\x0f\xac\x04"  # group cipher suite: CCMP
        b"\x01\x00"          # pairwise cipher suite count
        b"\x00\x0f\xac\x04"  # pairwise cipher suite: CCMP
        b"\x01\x00"          # auth key management suite count
        b"\x00\x0f\xac\x02"  # AKM: PSK
        b"\x00\x00"          # RSN capabilities
    ))
    return RadioTap() / dot11 / beacon / essid / ds_set / rsn


def _make_data_frame(bssid, client_mac):
    """Simulate a QoS data frame from a client associated to ``bssid``."""
    dot11 = Dot11(type=2, subtype=0, addr1=bssid, addr2=client_mac, addr3=bssid)
    return RadioTap() / dot11


def test_packet_handler_records_new_access_point(ws):
    beacon = _make_beacon()

    ws.packet_handler(beacon)

    assert LAB_AP_BSSID in ws.access_points
    info = ws.access_points[LAB_AP_BSSID]
    assert info["ssid"] == LAB_SSID
    assert info["channel"] == 6
    # The beacon advertises privacy (encryption enabled); exact cipher-suite
    # naming is Scapy's own parsing detail, so just assert it isn't "open".
    assert info["crypto"] not in ("N/A", set(), None)


def test_packet_handler_ignores_non_beacon_frames(ws):
    data_frame = _make_data_frame(LAB_AP_BSSID, LAB_CLIENT_MAC)

    ws.packet_handler(data_frame)

    assert ws.access_points == {}


def test_packet_handler_is_idempotent_for_repeated_beacons(ws):
    beacon = _make_beacon()

    ws.packet_handler(beacon)
    ws.packet_handler(beacon)

    assert len(ws.access_points) == 1


def test_packet_handler1_records_client_of_target_bssid(ws):
    ws.gateway_mac = LAB_AP_BSSID
    data_frame = _make_data_frame(LAB_AP_BSSID, LAB_CLIENT_MAC)

    ws.packet_handler1(data_frame)

    assert LAB_CLIENT_MAC in ws.unique_clients


def test_packet_handler1_ignores_clients_of_other_bssids(ws):
    ws.gateway_mac = LAB_AP_BSSID
    other_bssid = "02:00:00:00:00:99"
    data_frame = _make_data_frame(other_bssid, LAB_CLIENT_MAC)

    ws.packet_handler1(data_frame)

    assert ws.unique_clients == {}
