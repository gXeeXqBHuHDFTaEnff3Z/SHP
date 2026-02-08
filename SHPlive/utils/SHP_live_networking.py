#!/usr/bin/env python3

import datetime
import sys
import struct
import socket
import traceback
from scapy.all import sniff, Ether, ARP, ICMP, IP, sendp, send, conf, show_interfaces

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


# ========== ICMP-based Covert Channel Functions (WAN-capable) ==========

def prepare_icmp_sender(target_ip: str):
    """
    Prepares a fast ICMP sender function for a given target IP.

    The returned function accepts two 8-bit binary strings (bitstrings) and:
      1) Encodes the first bitstring in the ICMP ID field (16-bit, using lower 8 bits)
      2) Encodes the second bitstring in the ICMP Sequence field (16-bit, using lower 8 bits)
      3) Sends an ICMP Echo Request (ping) packet

    This enables covert channel communication over WAN using ICMP timing patterns.

    Usage:
      icmp_sender = prepare_icmp_sender("8.8.8.8")
      icmp_sender("00000000", "00000000")  # INIT message
      icmp_sender("11111111", "11111101")  # Data pointer
      icmp_sender("11111111", "11111110")  # STOP message

    Args:
        target_ip: Destination IP address for ICMP packets

    Returns:
        Function that accepts (bitstring_id, bitstring_seq, return_packet=False)
    """

    def icmp_sender(bitstring_id: str, bitstring_seq: str, return_packet: bool = False):
        """
        Sends an ICMP Echo Request with encoded bitstrings.

        Args:
            bitstring_id: 8-bit binary string to encode in ICMP ID field
            bitstring_seq: 8-bit binary string to encode in ICMP Sequence field
            return_packet: If True, return packet instead of sending (for testing)

        Raises:
            ValueError: If bitstrings are invalid (not 8 bits or not binary)
        """
        # Validate bitstrings
        if len(bitstring_id) != 8 or not all(c in '01' for c in bitstring_id):
            raise ValueError(f"Invalid ID bitstring: {bitstring_id}. Must be 8 binary digits.")
        if len(bitstring_seq) != 8 or not all(c in '01' for c in bitstring_seq):
            raise ValueError(f"Invalid Seq bitstring: {bitstring_seq}. Must be 8 binary digits.")

        # Convert bitstrings to integers
        icmp_id = int(bitstring_id, 2)
        icmp_seq = int(bitstring_seq, 2)

        # Validate range (should be 0-255 for 8-bit values)
        if not (0 <= icmp_id < 256):
            raise ValueError(f"Invalid ICMP ID value: {icmp_id}. Must be 0-255.")
        if not (0 <= icmp_seq < 256):
            raise ValueError(f"Invalid ICMP Seq value: {icmp_seq}. Must be 0-255.")

        # Build ICMP Echo Request packet
        # Type 8 = Echo Request, Code 0
        pkt = IP(dst=target_ip) / ICMP(type=8, code=0, id=icmp_id, seq=icmp_seq)

        # Return packet for testing or send it
        if return_packet:
            return pkt
        else:
            # Send at layer 3 (IP) - works across routed networks
            send(pkt, verbose=False)

    return icmp_sender


def send_icmp_request(icmp_sender, bitstring_id, bitstring_seq):
    """
    Sends an ICMP request using the provided sender function and bitstring parameters.
    Logs the timestamp and parameters on success, logs errors on failure.

    This is the ICMP equivalent of send_arp_request() for WAN environments.

    Args:
        icmp_sender (callable): Function that sends the actual ICMP request
        bitstring_id (str): First bitstring parameter (encoded in ICMP ID)
        bitstring_seq (str): Second bitstring parameter (encoded in ICMP Sequence)

    Raises:
        Exception: Logs any exceptions that occur during ICMP request sending
    """
    try:
        icmp_sender(bitstring_id, bitstring_seq)

        # Command-line feedback with timestamp
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # Uncomment for debugging:
        # print(f"[INFO] ICMP-Pointer sent @[{timestamp}] with options [{bitstring_id}:{bitstring_seq}]")

    except Exception as e:
        print(f"[ERR!] sending ICMP pointer with options [{bitstring_id}:{bitstring_seq}]: {e}")


def is_covert_icmp_pointer(packet, target_ip):
    """
    Checks if 'packet' is an ICMP Echo Request whose destination IP matches 'target_ip'.
    If so, extracts the bitstrings encoded in the ICMP ID and Sequence fields.

    This is the ICMP equivalent of is_covert_pointer() for WAN environments.

    Args:
        packet: A scapy packet
        target_ip: Target IP address to match (destination of ICMP packet)

    Returns:
        tuple: (bool, str, str) - (is_covert, id_bitstring, seq_bitstring)
               - is_covert: True if packet is a covert ICMP pointer
               - id_bitstring: 8-bit binary string from ICMP ID field
               - seq_bitstring: 8-bit binary string from ICMP Sequence field
               Returns (False, '', '') if not a covert packet
    """
    # Ensure this is an ICMP Echo Request packet
    if ICMP in packet and IP in packet:
        # Check if it's an Echo Request (type 8)
        if packet[ICMP].type == 8:
            # Check if destination matches our target IP
            if packet[IP].dst == target_ip:
                # Extract ICMP ID and Sequence fields
                icmp_id = packet[ICMP].id
                icmp_seq = packet[ICMP].seq

                # Convert to 8-bit binary strings (take lower 8 bits)
                # Use modulo to handle cases where fields might be > 255
                id_bitstring = f"{icmp_id & 0xFF:08b}"
                seq_bitstring = f"{icmp_seq & 0xFF:08b}"

                return True, id_bitstring, seq_bitstring

    return False, "", ""

