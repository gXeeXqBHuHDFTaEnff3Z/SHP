#!/usr/bin/env python3

import datetime
import sys
import struct
import socket
import traceback
from scapy.all import sniff, Ether, ARP, sendp, conf, show_interfaces

#STATIC_IP_CC             = '127.55.0.0' for local testing
STATIC_IP_CC             = '10.59.0.0'
STATIC_BITSTRING_INIT    = '00000000'
STATIC_BITSTRING_POINTER = '00000001'
STATIC_BITSTRING_RETRY   = '00000010'
STATIC_BITSTRING_STOP    = '00000011'

def check_scapy_sniff_permission():
    """
    Attempt a minimal sniff to verify that Scapy has permission 
    to open a raw socket. If it cannot, terminate the script.
    """
    try:
        # Perform a minimal sniff with count=0 and a very short timeout
        # (this effectively just tests if a raw socket can be opened)
        sniff(count=0, timeout=0.1)
    except Exception as e:
        stacktrace = traceback.format_exc()
        
        print("[ERROR] Scapy sniff permission check failed:")
        print(f"  {e}: {stacktrace}")
        print("You must run this script with root privileges or use sudo.")
        sys.exit(1)
        
def ip_to_int(ip_str: str) -> int:
    """
    Convert dotted IPv4 string to a 32-bit integer.
    """
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]

def int_to_ip(ip_int: int) -> str:
    """
    Convert a 32-bit integer to a dotted IPv4 string.
    """
    return socket.inet_ntoa(struct.pack("!I", ip_int))

def display_interfaces_and_selected(selected_iface=None):
    """
    Displays all available interfaces and shows which interface will be used
    for sniffing. If 'selected_iface' is None, it falls back to Scapy's default
    interface.
    """
    print("=== Available Interfaces ===")
    show_interfaces()  # Lists interfaces and related details

    # Determine which interface will be used (selected_iface or Scapy's default)
    default_iface = conf.iface
    used_iface = selected_iface if selected_iface else default_iface

    print(f"\n=== Currently Recording from: {used_iface} ===\n")    

def find_and_select_active_interface():
    """
    Attempts to find the active interface by asking Scapy which interface
    it would use to route packets to a well-known public IP (e.g., 8.8.8.8).
    Sets scapy.conf.iface to that interface and returns the interface name.
    """
    from scapy.all import conf

    # Ask Scapy’s routing mechanism which interface is used to reach 8.8.8.8
    best_iface, gw, metric = conf.route.route("8.8.8.8")

    # Set Scapy's default interface to the detected one
    conf.iface = best_iface

    print(f"[INFO] Detected active interface: {best_iface}")
    print(f"[INFO] Default gateway for this route: {gw} (metric {metric})")

    return best_iface
   
def prepare_arp_sender(base_ip: str):
    """
    Prepares a fast ARP sender function for a given base IP.

    The returned function accepts two 8-bit binary strings (bitstrings) and:
      1) Creates a new IP by combining the base IP's first 2 octets
         with the input bitstrings as the 3rd and 4th octets.
      2) Sends an ARP request (who-has).

    Usage:
      arp_sender = prepare_arp_sender("192.168.1.10")
      arp_sender("00000000", "00000000") # empty message
      arp_sender("11111111", "11111101") # connection init
      arp_sender("11111111", "11111110") # connection stop
      ...
    """
    # Convert the base IP into an integer
    base_ip_int = ip_to_int(base_ip)
    # Zero out the last 16 bits (last two octets) so we can replace them quickly
    # Mask = 0xFFFF0000 means "keep top 16 bits, discard bottom 16 bits"
    base_ip_16 = base_ip_int & 0xFFFF0000

    def arp_sender(bitstring3rd: str, bitstring4th: str):
        # Convert the bitstrings to integers
        octet3 = int(bitstring3rd, 2)
        octet4 = int(bitstring4th, 2)
        
        # Validate both octets
        if not (0 <= octet3 < 256):
            raise ValueError(f"Invalid 3rd octet bitstring: {bitstring3rd}")
        if not (0 <= octet4 < 256):
            raise ValueError(f"Invalid 4th octet bitstring: {bitstring4th}")

        # Combine base IP's first 2 octets with our new 3rd and 4th octets
        # Shift 3rd octet left by 8 bits and combine with 4th octet
        final_octets = (octet3 << 8) | octet4
        final_ip_int = base_ip_16 | final_octets
        final_ip_str = int_to_ip(final_ip_int)

        # Build ARP packet
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1,              # ARP request
            pdst=final_ip_str, # Our target IP
            hwdst="ff:ff:ff:ff:ff:ff"
        )

        # Send at layer 2 (Ethernet) - usually faster
        sendp(pkt, verbose=False)

    return arp_sender
    
def prepare_arp_receiver(base_ip: str):
    """
    Returns a function that handles incoming ARP packets by:
      1) Checking if the ARP is a request (op=1).
      2) Checking if the destination IP’s first 3 octets match base_ip.
      3) Printing the 4th octet in bitstring (binary) form.

    Usage:
      handle_pkt = prepare_arp_receiver("192.168.1.10")
      sniff(filter="arp", store=False, prn=handle_pkt)
    """
    # Convert the base IP to int, then mask off the last 8 bits (lowest octet)
    base_ip_int = ip_to_int(base_ip)
    base_ip_24 = base_ip_int & 0xFFFFFF00  # keep top 24 bits

    def handle_arp_packet(packet):
        # Only process ARP requests (op=1)
        if ARP in packet and packet[ARP].op == 1:
            pdst_str = packet[ARP].pdst
            pdst_int = ip_to_int(pdst_str)
            # Check if the first 24 bits match our base IP’s first 24 bits
            if (pdst_int & 0xFFFFFF00) == base_ip_24:
                # Extract the last octet
                last_octet = pdst_int & 0xFF
                # Convert that octet to an 8-bit binary string
                bitstring = format(last_octet, '08b')
                # Print result
                print(f"[ARP] pdst={pdst_str} => 4th octet bitstring: {bitstring}")

    return handle_arp_packet

def send_arp_request(arp_sender, bitstring3rd, bitstring4th):
    """
    Sends an ARP request using the provided sender function and bitstring parameters.
    Logs the timestamp and parameters on success, logs errors on failure.

    Args:
        arp_sender (callable): Function that sends the actual ARP request
        bitstring3rd (str): Third bitstring parameter for the ARP request
        bitstring4th (str): Fourth bitstring parameter for the ARP request

    Raises:
        Exception: Logs any exceptions that occur during ARP request sending
    """
    try:
        arp_sender(bitstring3rd, bitstring4th)

        # Command-line feedback with timestamp
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        #print(f"[INFO] ARP-Pointer send @[{timestamp}] with options [{bitstring3rd}:{bitstring4th}]") # type: ignore

    except Exception as e:
        print(f"[ERR!] sending ARP pointer with options [{bitstring3rd}:{bitstring4th}]: {e}") # type: ignore

def is_covert_pointer(packet, ip):
    """
    Checks if 'packet' is an ARP request (op=1) whose destination IP matches
    the first two octets of 'ip'. If so, returns a tuple (True, third_octet_bits, fourth_octet_bits).
    Otherwise, returns (False, '', '').

    :param packet: A scapy packet.
    :param ip: An IP address in A.B.C.D format.
    :return: (bool, str, str) - (True/False, third_octet_bitstring, fourth_octet_bitstring).
    """
    # Ensure this is an ARP packet and an ARP request
    if ARP in packet and packet[ARP].op == 1:
        # Extract the first two octets from the provided IP
        ip_prefix = ".".join(ip.split(".")[:2])  # e.g. "192.168"
        
        # Extract the ARP destination IP and its first two octets
        arp_dst_ip = packet[ARP].pdst
        arp_dst_prefix = ".".join(arp_dst_ip.split(".")[:2])

        #print(f'[DEBG] {ip_prefix} == {arp_dst_ip} @[{packet.time}]?')
        
        # Compare the two prefixes
        if ip_prefix == arp_dst_prefix:
            # Get the third and fourth octets
            third_octet = int(arp_dst_ip.split(".")[2])
            fourth_octet = int(arp_dst_ip.split(".")[3])
            
            # Convert both octets to 8-bit binary strings
            third_octet_bits = f"{third_octet:08b}"
            fourth_octet_bits = f"{fourth_octet:08b}"
            
            return True, third_octet_bits, fourth_octet_bits

    return False, "", ""

def isValidPacket(packet):
    """Validates packet structure and returns boolean indicating if packet is valid"""
    if not packet:
        return False
    
    try:
        # Basic structure checks
        if not hasattr(packet, 'time') or not hasattr(packet, 'src') or not hasattr(packet, 'dst'):
            return False
            
        # Check for common corrupted packet indicators
        if len(packet) < 14:  # Minimum Ethernet frame size
            return False
            
        return True
    except Exception as e:
        print(f"[ERR!] Error in packet validation: {str(e)}")
        return False

