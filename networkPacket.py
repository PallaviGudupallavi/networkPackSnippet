# Importing necessary modules
import logging
from datetime import datetime
import subprocess
import sys
import platform

# Suppress scapy-related warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

try:
    from scapy.all import *
except ImportError:
    print("Scapy package for Python is not installed on your system.")
    sys.exit()

# Printing a message to the user
print("\n! Make sure to run this program as ROOT (or Administrator on Windows) !\n")

# Asking the user for input - the interface on which to run the sniffer
net_iface = input("* Enter the interface on which to run the sniffer (e.g., 'Wi-Fi' or 'Ethernet' or 'enp0s8'): ")

# Setting network interface in promiscuous mode (only for non-Windows systems)
if platform.system() != "Windows":
    try:
        subprocess.call(["ifconfig", net_iface, "promisc"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)
    except:
        print("\nFailed to configure interface as promiscuous.\n")
    else:
        print("\nInterface %s was set to PROMISCUOUS mode.\n" % net_iface)
else:
    print("\nRunning on Windows: Skipping PROMISCUOUS mode setting.\n")

# Asking the user for the number of packets to sniff (the "count" parameter)
pkt_to_sniff = input("* Enter the number of packets to capture (0 is infinity): ")

# Handling the packet count input
if int(pkt_to_sniff) != 0:
    print("\nThe program will capture %d packets.\n" % int(pkt_to_sniff))
else:
    print("\nThe program will capture packets until the timeout expires.\n")

# Asking the user for the time interval to sniff (the "timeout" parameter)
time_to_sniff = input("* Enter the number of seconds to run the capture: ")

# Handling the timeout input
if int(time_to_sniff) != 0:
    print("\nThe program will capture packets for %d seconds.\n" % int(time_to_sniff))

# Asking the user for protocol filter
proto_sniff = input("* Enter the protocol to filter by (arp|bootp|icmp|0 for all protocols): ")

# Handling the protocol input
if proto_sniff in ["arp", "bootp", "icmp"]:
    print("\nThe program will capture only %s packets.\n" % proto_sniff.upper())
elif proto_sniff == "0":
    print("\nThe program will capture all protocols.\n")
else:
    print("\nInvalid protocol specified. Capturing all protocols.\n")
    proto_sniff = "0"

# Asking the user for the log file name
file_name = input("* Please give a name to the log file (e.g., 'capture_log.txt'): ")

# Opening the log file
try:
    sniffer_log = open(file_name, "a")
except Exception as e:
    print(f"\nFailed to open log file: {e}\n")
    sys.exit()

# Packet processing function
def packet_log(packet):
    now = datetime.now()
    try:
        src_mac = packet.src
        dst_mac = packet.dst
    except AttributeError:
        src_mac = "N/A"
        dst_mac = "N/A"

    if proto_sniff == "0":
        print(f"Time: {now} Protocol: ALL SMAC: {src_mac} DMAC: {dst_mac}", file=sniffer_log)
    else:
        print(f"Time: {now} Protocol: {proto_sniff.upper()} SMAC: {src_mac} DMAC: {dst_mac}", file=sniffer_log)

# Informing the user that capture is starting
print("\n* Starting the capture...")

# Running the sniffing process
try:
    if proto_sniff == "0":
        sniff(iface=net_iface, count=int(pkt_to_sniff), timeout=int(time_to_sniff), prn=packet_log)
    else:
        sniff(iface=net_iface, filter=proto_sniff, count=int(pkt_to_sniff), timeout=int(time_to_sniff), prn=packet_log)
except Exception as e:
    print(f"\nAn error occurred during sniffing: {e}\n")
    sniffer_log.close()
    sys.exit()

# Printing the closing message
print(f"\n* Capture complete. Please check the '{file_name}' file to see the captured packets.\n")

# Closing the log file
sniffer_log.close()
