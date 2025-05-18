#!/usr/bin/env python3
"""
live-poi-generator.py
A script to generate ARP broadcasts, IPv4 broadcast UDP traffic, and IPv4 multicast traffic
at a user-specified average rate with random inter-packet intervals (to mimic typical LAN traffic).
Requires: scapy (pip install scapy)
"""

import sys
import time
import random
import argparse
import logging
from logging.handlers import RotatingFileHandler
import utils.SHP_live_networking as SHP_live_networking 

# Attempt to import Scapy; exit if not installed
try:
    from scapy.all import (
        conf,
        sendp,
        Ether,
        ARP,
        IP,
        UDP,
        Raw,
        RandShort
    )
except ImportError:
    print("Error: Scapy is not installed. Please install via 'pip install scapy' and try again.")
    sys.exit(1)

STATIC_AVERAGE_PACKETS = 120.0 # default: 120
STATIC_SUBNET = '10.0.0.0/8'

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Generate broadcast, multicast, and ARP traffic at a specified rate with random intervals."
    )
    parser.add_argument(
        "--subnet",
        default=STATIC_SUBNET,
        help="If set, use a random source IP from the given subnet (e.g., 192.168.0.0/24)"
    )
    parser.add_argument(
        "-r", "--rate",
        type=float,
        default=STATIC_AVERAGE_PACKETS,
        help=f"Average packets per second (default={STATIC_AVERAGE_PACKETS})"
    )
    parser.add_argument(
        "--arp",
        action="store_true",
        help="Enable ARP broadcast traffic"
    )
    parser.add_argument(
        "--broadcast-udp",
        action="store_true",
        help="Enable IPv4 broadcast UDP traffic (255.255.255.255)"
    )
    parser.add_argument(
        "--multicast",
        action="store_true",
        help="Enable IPv4 multicast traffic (224.0.0.x)"
    )
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to use (default: scapy.conf.iface)"
    )
    parser.add_argument(
        "--log-file",
        default="live-poi-generator.log",
        help="Log file for rotating logs (default=live-poi-generator.log)"
    )
    parser.add_argument(
        "--max-log-size",
        type=int,
        default=1024 * 1024,
        help="Maximum log file size in bytes before rotation (default=1MB)"
    )
    parser.add_argument(
        "--backup-count",
        type=int,
        default=5,
        help="Number of backup log files to keep (default=5)"
    )

    args = parser.parse_args()

    # Set up rotating logs
    logger = logging.getLogger("live-poi-generator")
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(args.log_file, maxBytes=args.max_log_size, backupCount=args.backup_count)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    handler.setFormatter(formatter)
    #logger.addHandler(handler)

    # Validate and prepare the subnet if provided
    if args.subnet:
        import ipaddress
        try:
            subnet_network = ipaddress.ip_network(args.subnet, strict=False)
            subnet_ips = list(subnet_network.hosts())
            if not subnet_ips:
                raise ValueError("No available hosts in the subnet")
        except ValueError as e:
            print(f"Error: Invalid subnet '{args.subnet}': {e}")
            sys.exit(1)

    # Validate user input for rate
    if args.rate <= 0:
        print("Error: The packet rate must be a positive number.")
        sys.exit(1)

    # Enable all traffic types if none selected
    if not (args.arp or args.broadcast_udp or args.multicast):
        args.arp = True
        args.broadcast_udp = True
        args.multicast = True

    # Use specified interface if provided
    if args.interface:
        conf.iface = args.interface
    else:
         # Detect and set the active interface cross-platform
        conf.iface = SHP_live_networking.find_and_select_active_interface()

    # Logging basic info
    print(f"Starting live-poi-generator on interface '{conf.iface}' at ~{args.rate} packets/sec.")
    logger.info(f"Starting generator on interface '{conf.iface}' at ~{args.rate} pps.")

    # Packet generator functions
    def generate_arp():
        """Generate an ARP request using IPs from the provided subnet if set."""
        if args.subnet:
            src_ip = str(random.choice(subnet_ips))
            dst_ip = src_ip
            while dst_ip == src_ip:
                dst_ip = str(random.choice(subnet_ips))
            return Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(psrc=src_ip, pdst=dst_ip)
        else:
            random_ip = f"192.168.1.{random.randint(1, 254)}"
            return Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=random_ip)


    def generate_broadcast_udp():
        """Generate an IPv4 UDP packet to the broadcast IP."""
        ip_layer = IP(dst="255.255.255.255")
        if args.subnet:
            ip_layer.src = str(random.choice(subnet_ips))
        return (Ether(dst="ff:ff:ff:ff:ff:ff") /
                ip_layer /
                UDP(sport=RandShort(), dport=RandShort()) /
                Raw(load=b"Broadcast test"))


    def generate_multicast_udp():
        """Generate an IPv4 UDP packet to a random 224.0.0.x address with matching L2 multicast MAC."""
        last_octet = random.randint(1, 255)
        mcast_ip = f"224.0.0.{last_octet}"
        mcast_mac = f"01:00:5e:00:00:{last_octet & 0x7F:02x}"
        ip_layer = IP(dst=mcast_ip)
        if args.subnet:
            ip_layer.src = str(random.choice(subnet_ips))
        return (Ether(dst=mcast_mac) /
                ip_layer /
                UDP(sport=RandShort(), dport=RandShort()) /
                Raw(load=b"Multicast test"))


    # Build list of active packet types
    generators = []
    if args.arp:
        generators.append(generate_arp)
    if args.broadcast_udp:
        generators.append(generate_broadcast_udp)
    if args.multicast:
        generators.append(generate_multicast_udp)

    # Calculate the average interval for sending packets
    avg_interval = 1.0 / args.rate
    packet_count = 0
    start_time = time.time()

    try:
        while True:
            # Pick a random generator from active types
            pkt_gen = random.choice(generators)
            # Craft the packet
            packet = pkt_gen()
            # Send packet on layer 2
            sendp(packet, iface=conf.iface, verbose=False)
            packet_count += 1

            # Apply random jitter: uniform factor between 0.5x and 1.5x
            jitter_factor = random.uniform(0.5, 1.5)
            time.sleep(avg_interval * jitter_factor)

            # Print/log stats every 50 packets
            if packet_count % 50 == 0:
                elapsed = time.time() - start_time
                current_rate = packet_count / elapsed if elapsed > 0 else 0
                print(f"Sent {packet_count} packets (~{current_rate:.2f} pps)")
                logger.info(f"Sent {packet_count} packets (~{current_rate:.2f} pps)")

    except KeyboardInterrupt:
        print("\nInterrupted by user, shutting down.")
        logger.info(f"Shutting down after sending {packet_count} packets.")
        sys.exit(0)
    except Exception as e:
        print(f"An error occurred: {e}")
        logger.exception("Exception in traffic generation loop")
        sys.exit(1)


if __name__ == "__main__":
    main()
