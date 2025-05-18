#!/usr/bin/env python3

import argparse
from queue import Full
import time
import scapy
from scapy.all import sniff, wrpcap
from scapy.config import conf
#conf.debug_dissector = 2 # debug full scapy error
import threading
import logging
import datetime
import os
import socket
import utils.SHP_algos as SHP_algos
import utils.SHP_ecc as SHP_ecc
import utils.SHP_live_networking as SHP_live_networking
import traceback

STATIC_VERSION = '3.3'

# options
DEFAULT_POI     = 'broadcast_bpf'# # broadcast_bpf, all, port, subnet, broadcast_domain
DEFAULT_REFERENCE = 'direct' # direct, last_poi
DEFAULT_RTT     = 0 # in milliseconds
DEFAULT_SILENCE = 2 # in milliseconds
DEFAULT_INPUTSOURCE = 'ISD'
DEFAULT_SUBCHANNELING = 'none'
DEFAULT_SUB_BITS  = 0 # 0-8
DEFAULT_BITLENGTH = 3 # 0-8
DEFAULT_ROUNDING  = 0 # 0-6
DEFAULT_REHASHING = 2 # 0-8
DEFAULT_ECC       = 'none' # live ecc is still experimental
DEFAULT_SECRET = 'secret_message_short.txt'
DEFAULT_SAVEPCAP = False
DEFAULT_LOGGING = logging.INFO

# global variables for sending
index = 0
last_data_per_subchannel = {}
last_poi_time = None
last_cc_time = 0
list_last_data_pois = []
send_chunks = set()
stop_sniffing = False

# global variables for tracking statistics
script_start_time = None
timestamp_start = 0
timestamp_terminate = None
counter_total_packets_received = 0
counter_poi_ignored_because_silence = 0
counter_poi_valid_received = 0
counter_matches = 0
counter_secret_bits_transmitted = 0
counter_retries_received = 0
secret_message_sent = False

# Get the absolute path of the current script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Build the full path for the log file
log_file = os.path.join(script_dir, 'SHPclient.log')

# Configure logging for error tracking
logging.basicConfig(
    level=DEFAULT_LOGGING,
    format='%(asctime)s - %(levelname)s - %(message)s',
    #datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        #logging.FileHandler(log_file),  # Write to file
        logging.StreamHandler()         # Also write to console
    ]
)

# Define file for storing captured packets
packet_pcap_file = os.path.join(script_dir, 'SHPclient.pcapng')

# Check if pcap file exists; if not, create an empty one
if not os.path.exists(packet_pcap_file):
    open(packet_pcap_file, 'wb').close()  # Create an empty file if it doesn't exist

# Parse command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Packet capture and filtering based on POI, port, and subnet.")
    # arguments for poi filtering
    parser.add_argument('--poi', type=str, default=DEFAULT_POI, help="Packet of interest type.")  # all, port, subnet, broadcast_domain, broadcast_bpf
    parser.add_argument('--reference', choices=['last_poi', 'direct'], default=DEFAULT_REFERENCE, help="Packet the pointer is referencing.")
    parser.add_argument('--rtt', type=int, default=DEFAULT_RTT, help="Round Trip Time in ms between CS and CR, for timing recalculation.")
    parser.add_argument('--silence_poi', type=args_check_silence, default=DEFAULT_SILENCE, help='Number of milliseconds any two PoI need to be apart (= phi or POI silence interval). Default 0 = disabled. Max 1000ms.')
    parser.add_argument('--silence_cc', type=args_check_silence, default=DEFAULT_SILENCE, help='Number of milliseconds any two CC messages need to be apart (= d or CC silence interval). Default 0 = disabled. Max 1000ms.')
    parser.add_argument('--port', type=int, choices=range(0, 65536), default=443, help="Port number for POI (0-65535).")
    parser.add_argument('--subnet', type=str, default="10.0.0.0/8", help="Subnet for POI function (e.g., '192.168.1.0/24').")

    # arguments for SHP algorithm
    parser.add_argument('--inputsource', choices=['IPD', 'ISD', 'ISPN', 'ICD', 'timestamp', 'payload', 'tcp_seq'], default=DEFAULT_INPUTSOURCE, help='Defines source of the pointer data. Default=ISD.') # IPD=inter packet delay; ISD=inter signal delay; ISPN=inter signal packet number
    parser.add_argument('--deskew', choices=['none', 'sha3', 'md5', 'log', 'power'], default='sha3', help='Defines deskew transformation.')
    parser.add_argument('--rounding_factor', type=int, default=DEFAULT_ROUNDING, help='Rounding factor.')
    parser.add_argument('--bitlength', type=int, default=DEFAULT_BITLENGTH, help='Number of bits for hash and message comparison.') # basic chest length
    parser.add_argument('--subchanneling', choices=['none', 'baseipd', 'iphash', 'clock', 'clockhash'], default=DEFAULT_SUBCHANNELING, help='Defines how subchannel split is calculated.')
    parser.add_argument('--subchanneling_bits', type=int, default=DEFAULT_SUB_BITS, help='Number of bits used for multiplex subchannel number. Default=0')
    parser.add_argument('--ecc', choices=['none', 'hamming', 'hamming+', 'inline-hamming+'], default=DEFAULT_ECC, help='Type of error correction code. Allows matching near miss sequences. Default none.')
    parser.add_argument('--multihashing', type=args_check_multihashing, default=DEFAULT_REHASHING, help='Number of bits used to mark how many hash iterations are needed to determine the message chunk. Default 0 = disabled. ')
    parser.add_argument('--ooodelivery', type=int, default=0, help='Number of bits used to mark the future message chunk, determining the number of future chunks to be checked. Default 0 = disabled. Maximum allowed value is 8.') # assumes CR supports packet reordering 

    parser.add_argument('--path_secret', type=str, default=DEFAULT_SECRET, help='File path containing the secret message.')

    # argument for saving PCAPs
    parser.add_argument("--savepcap", action="store_true", default=DEFAULT_SAVEPCAP, help="Enable savepcap mode.")
    
    return parser.parse_args()

def args_check_silence(value: str) -> int:
    """Ensure that the silence value is between 0 and 1000."""
    ivalue = int(value)
    if ivalue < 0 or ivalue > 1000:
        raise argparse.ArgumentTypeError(
            f"{value} is an invalid value for --silence. It must be between 0 and 1000."
        )
    return ivalue

def args_check_multihashing(value: str) -> int:
    """Ensure that the multihashing value is between 0 and 8."""
    ivalue = int(value)
    if ivalue < 0 or ivalue > 8:
        raise argparse.ArgumentTypeError(
            f"{value} is an invalid value for --multihashing. It must be between 0 and 8."
        )
    return ivalue

# Capture Packet Function
def capture_packets(poi, reference, rtt, silence_poi, silence_cc, port, subnet, inputsource, deskew, bitlength, rounding_factor, subchanneling, subchanneling_bits, multihashing, ooodelivery, ecc, path_secret, savepcap):
    
    global script_start_time, timestamp_terminate, total_bits, total_chunks
    global stop_sniffing

    script_start_time = time.time()

    # Fetch all reusable variables
    # Get the full path of the current script
    script_path = os.path.abspath(__file__)
    # Get the directory of the script
    script_dir = os.path.dirname(script_path)

    secret_message = SHP_algos.read_secret_message(os.path.join(script_dir, path_secret))
    secret_message_bitstring = SHP_algos.string_to_bitstring(secret_message)
    checksum_length = SHP_ecc.get_checksum_length(ecc, bitlength)

    # Pad the secret_message_bitstring with zeros to make its length a multiple of bitlength
    padding_length = (bitlength - (len(secret_message_bitstring) % bitlength)) % bitlength
    secret_message_bitstring = secret_message_bitstring.ljust(len(secret_message_bitstring) + padding_length, '0')

    logging.info(f"Loaded secret from {os.path.basename(path_secret)}, with length {len(secret_message_bitstring)}, [{secret_message_bitstring[:32]}]")
 
    # Compute total bits and total chunks
    total_bits = len(secret_message_bitstring)
    total_chunks = total_bits // bitlength

    def packet_handler(packet):
        """Wrapper function to handle packet processing with error handling"""
        try:
            process_packet(packet, poi, reference, rtt, silence_poi, silence_cc, port, subnet, inputsource, deskew, bitlength, rounding_factor,
                         subchanneling, subchanneling_bits, multihashing, ooodelivery, ecc, checksum_length, secret_message_bitstring, savepcap)
        except scapy.error.Scapy_Exception as e:
            logging.warning(f"Skipping malformed packet: {str(e)}")
            time.sleep(1)
        except Exception as e:
            stacktrace = traceback.format_exc()
            logging.error(f"Error processing packet: {str(e)} with stacktrace {stacktrace}")
        return
    
    # Whitelisting only protocols we want to dissect for speed and reducing error complexity
    conf.protocol_whitelist = [
        "Ethernet", "IP", "IPv6", "ARP", 
        # "DNS" is *not* listed here, so DNS gets skipped
    ]

    try:
        if (poi == 'broadcast_bpf'):
            bpf_filter = SHP_algos.STATIC_BPF_FILTER
        else:
            bpf_filter = ''

        # Configure sniffing with error handlers
        sniff(
            prn=packet_handler,  # Process each packet
            store=False,  # Don't store packets in memory
            stop_filter=lambda _: stop_sniffing,  # Check stop condition
            iface=active_iface,
            monitor=False,  # Disable monitor mode
            filter=bpf_filter,  # BPF filter - or filter in software
            quiet=False,  # Suppress scapy's output
            timeout=None,  # Run indefinitely
            started_callback=lambda: logging.info(f"Packet capture started...")
        )
    except KeyboardInterrupt:
        logging.info("Capture stopped by user")
        stop_sniffing = True
    except socket.error as se:
        stacktrace = traceback.format_exc()
        logging.error(f"Socket error during capture: {str(se)} with stacktrace: {stacktrace}")
        stop_sniffing = True
    except Exception as e:
        stacktrace = traceback.format_exc()
        logging.error(f"Critical capture error: {str(e)} with stacktrace: {stacktrace}")
        stop_sniffing = True
    finally:
        logging.info("Capture thread terminated")
        timestamp_terminate = time.time()
        SHP_live_networking.send_arp_request(arp_sender, SHP_live_networking.STATIC_BITSTRING_STOP, SHP_live_networking.STATIC_BITSTRING_STOP)
        write_statistics(poi, inputsource, bitlength, rounding_factor, subchanneling, subchanneling_bits, ecc, multihashing)
        display_statistics()

# Process Packet: Filter and Log to File
def process_packet(packet, poi, reference, rtt, silence_poi, silence_cc, port, subnet, inputsource, deskew, bitlength, rounding_factor, subchanneling, subchanneling_bits, multihashing, ooodelivery, ecc, checksum_length, secret_message_bitstring, savepcap):
    global index
    global timestamp_start
    global last_data_per_subchannel
    global last_poi_time
    global last_cc_time
    global list_last_data_pois
    global send_chunks
    global counter_matches
    global counter_total_packets_received
    global counter_poi_ignored_because_silence
    global counter_poi_valid_received
    global counter_secret_bits_transmitted
    global counter_retries_received
    global secret_message_sent
    global stop_sniffing

    counter_total_packets_received += 1  # Increment total packets received

    # check if packet is generally a valid packet
    # if not SHP_live_networking.isValidPacket(packet):
    #    logging.warning(f"Invalid packet on wire, skipped.")
    #    return    

    # Check if packet is POI
    if (poi == 'broadcast_bpf') or (poi == 'all'):
        isPOI = True
    else:
        isPOI = SHP_algos.isPOI(packet, poi=poi, port=port, subnet=subnet, ignored=None)

    # ignore non-POI traffic
    if not isPOI:
        return
    
    # -> its a valid POI   
    logging.debug(f'{packet.time} POI')

    # Write all POI packets to PCAPNG file
    if savepcap:
        write_packet_to_file(packet)

    # have we send the start signal?
    if (timestamp_start == 0):
        SHP_live_networking.send_arp_request(arp_sender, SHP_live_networking.STATIC_BITSTRING_INIT, SHP_live_networking.STATIC_BITSTRING_INIT)
        timestamp_start = time.time()
        logging.info(f"{timestamp_start} START signal sent.")
        return
    
    # have we waited after the start signal?
    if (packet.time - timestamp_start) < (silence_cc / 1000):
        return

    # might be a covert channel message. 
    isCovert, bits3, bits4 = SHP_live_networking.is_covert_pointer(packet, SHP_live_networking.STATIC_IP_CC)

    if isCovert:
        # handle retry
        if (bits4 == SHP_live_networking.STATIC_BITSTRING_RETRY):
            counter_retries_received += 1
            counter_secret_bits_transmitted -= bitlength

            if (index > 0):
                index -= 1

            if (inputsource == 'ISPN'):
                last_data_per_subchannel[0] = 0

            if (inputsource in ['ISD', 'ICD', 'timestamp']):
                last_data_per_subchannel[0] = packet.time - (rtt / 2000) # new last signal is this retry minus RTT/2

            logging.warning(f"{packet.time} GOT RETRY [{bits3}:{bits4}]. Decreasing index to {index}. Last data: {last_data_per_subchannel}")
            time.sleep(0.5)  # Sleeps for 500 milliseconds
            return
        
        # observe CC minimum silence delta
        if (packet.time - last_cc_time < (silence_cc / 1000)):
            logging.debug(f"{packet.time} (silence: CC message in CC silence interval ({(packet.time - last_cc_time)}s). Ignoring it as POI.)")
            counter_poi_ignored_because_silence += 1
            last_cc_time = packet.time
            return

        last_cc_time = packet.time

        # we ignore CC as POI
        logging.debug(f"{packet.time} (Observed CC message [{bits3}][{bits4}]. Ignoring it as POI.)")
        return

    # data channel POI

    # observe POI minumum silence
    count_poi_in_silence, _ = SHP_algos.flush_poi_list(packet, list_last_data_pois, silence_poi)
    counter_poi_ignored_because_silence += count_poi_in_silence
    if (count_poi_in_silence > 0):
        delta = packet.time - last_cc_time
        logging.debug(f"{packet.time} (Silence: data channel POI too close to each other with delta: {delta*1000} < {silence_poi} ). Ignoring it as POI.)")
        return

    # still a poi after removing CC and silenced POI?
    if isPOI:
        #logging.debug(f'{packet.time} POI checking for match')

        counter_poi_valid_received += 1  # Increment POI packets received

        # Check if packet matches the data we want to send. this also updates matching counters.
        match, source_data, message_bits, deskewed_bits, subchannel, checking_index, multihash_count = SHP_algos.isMatch(
            packet, inputsource, deskew, bitlength, rounding_factor, subchanneling, subchanneling_bits, multihashing, ooodelivery, ecc, 
            checksum_length, secret_message_bitstring, index, timestamp_start, last_data_per_subchannel, last_poi_time, send_chunks)

        if match:
            # Calculate experiment verification checksum
            checksum = SHP_ecc.compute_checksum_6bit(message_bits)

            # if we use multihashing, calculate pointer counter bitstring
            if (multihashing > 0):
                multihash_count = f'{multihash_count:08b}' # pad with zeros, use 8 digits, binary format 
            else:
                multihash_count = SHP_live_networking.STATIC_BITSTRING_INIT
            
            # send data pointer 
            SHP_live_networking.send_arp_request(arp_sender, multihash_count, f"{checksum}01")

            logging.info(f'{packet.time} MATCH | source:{source_data} -> msg:{message_bits}| poi@{packet.time} | index {checking_index} | last data {last_data_per_subchannel}')

            counter_matches += 1
            counter_secret_bits_transmitted += bitlength  # Update secret bits transmitted

            if (inputsource == 'ISD'): # if we use inter signal timing, NOW is a signal
                last_data_per_subchannel[subchannel] = packet.time
            elif (inputsource == 'ISPN'): # if we use signal distance, distance is now 0
                last_data_per_subchannel[subchannel] = 0
                            
            if (ooodelivery <= 0):
                index = (index + 1) % (len(secret_message_bitstring) * 8 // bitlength)
            else:
                # add send message chunk to list of send chunks
                send_chunks.add(checking_index)
                # update first message chunk to be send. skip multiple indices if already sent. 
                if (checking_index == index):
                    while index in send_chunks:
                        index = (index + 1) % (len(secret_message_bitstring) * 8 // bitlength)
                        if (index == 0):
                            break

                if len(send_chunks) >= (len(secret_message_bitstring) * 8 // bitlength):
                    secret_message_sent = True  # All bits sent

            if counter_secret_bits_transmitted > len(secret_message_bitstring):
                secret_message_sent = True  # All bits sent    

            if secret_message_sent:
                stop_sniffing = True
                logging.info(f"{packet.time} Secret message has been fully sent, shutting down.")

        last_poi_time = packet.time
        list_last_data_pois.insert(0, packet)

        return

# Write Packet to PCAPNG File
def write_packet_to_file(packet):
    try:
        wrpcap(packet_pcap_file, packet, append=True)  # Append packet to the PCAPNG file
    except Exception as e:
        logging.error("Error writing packet to PCAPNG file: %s", e)

# Display statistics upon termination
def display_statistics():
    duration = (timestamp_terminate - script_start_time)
    print("\n=== Statistics ===")
    print("Script run duration: {:.2f} seconds".format(duration))
    print("Secret bits transmitted: {}".format(counter_secret_bits_transmitted))

    if duration > 0:
        bits_per_second = counter_secret_bits_transmitted / duration
        print("Bits per second transmitted: {:.2f}".format(bits_per_second))
    else:
        print("Bits per second transmitted: N/A")

    print("Packets of interest received: {}".format(counter_poi_valid_received))
    print("Retries received: {}".format(counter_retries_received))
    print("Total packets received: {}".format(counter_total_packets_received))

def write_statistics(poi, inputsource, bitlength, rounding_factor, subchanneling, subchanneling_bits, ecc, multihashing):
    import csv
    file_path = os.path.join(script_dir, 'stats_client.csv')
    # Data to write
    duration = (timestamp_terminate - timestamp_start)
    date_str = datetime.datetime.now().isoformat()
    matches_per_second = counter_matches / duration if duration > 0 else 0
    bits_per_second = counter_secret_bits_transmitted / duration if duration > 0 else 0
    print(f"Start: {timestamp_start}, Terminate: {timestamp_terminate}, Duration: {duration}")
    comment = f'Version {STATIC_VERSION}'    

    stats = {
        'date': date_str,
        'poi': poi,
        'inputsource': inputsource,
        'bitlength': bitlength,
        'rounding_factor': rounding_factor,
        'subchanneling': subchanneling,
        'subchanneling_bits': subchanneling_bits,
        'ecc': ecc,
        'multihashing': multihashing,
        "counter_total_packets_received": counter_total_packets_received,
        "counter_poi_ignored_because_silence": counter_poi_ignored_because_silence,
        "counter_poi_valid_received": counter_poi_valid_received,
        "counter_matches": counter_matches,
        "counter_data_bits_transmitted": counter_secret_bits_transmitted,
        "mps": matches_per_second,
        "bps": bits_per_second,
        "counter_retries_received": counter_retries_received,
        "script_start_time": script_start_time,
        "duration": duration,
        'comment': comment
    }
    
    file_exists = False
    try:
        with open(file_path, mode='r') as file:
            file_exists = True
    except FileNotFoundError:
        pass
    
    with open(file_path, mode='a', newline='') as file:
        writer = csv.writer(file, delimiter=',')
        if not file_exists:
            writer.writerow(stats.keys())  # Write headers only if file does not exist
        writer.writerow(stats.values())  # Write values

    logging.info(f"Statistics written to {file_path}")

# Start Packet Capture in a Thread
def start_shpclient(arp_sender, poi, reference, rtt, silence_poi, silence_cc, port, subnet, inputsource, deskew, bitlength, rounding_factor, subchanneling, subchanneling_bits, multihashing, ooodelivery, ecc, secret, savepcap):
    global timestamp_start

    try:
        logging.info(f"Starting SHPclient (= covert sender) with parameters: poi={poi}, inputsource={inputsource}, bitlength={bitlength}, multihashing={multihashing}, ecc={ecc}, savepcap={savepcap}")

        # start thread for packet capture
        capture_thread = threading.Thread(target=capture_packets, args=(poi, reference, rtt, silence_poi, silence_cc, port, subnet, inputsource, deskew, bitlength, rounding_factor, subchanneling, subchanneling_bits, multihashing, ooodelivery, ecc, secret, savepcap))
        capture_thread.daemon = True  # Ensures thread exits when main program exits
        capture_thread.start()
        capture_thread.join()  # Wait for thread to complete

    except Exception as e:
        stacktrace = traceback.format_exc()
        logging.error(f"Failed to start SHPclient: {e}: {stacktrace}")

if __name__ == "__main__":
    # clear screen
    #os.system('cls' if os.name == 'nt' else 'clear')
    
    args = parse_arguments()

    # Detect and set the active interface cross-platform
    active_iface = SHP_live_networking.find_and_select_active_interface()

    # check if we can open sockets
    SHP_live_networking.check_scapy_sniff_permission()

    # list interfaces recorded
    # SHP_live_networking.display_interfaces_and_selected(selected_iface=active_iface)

    # prepare our sockets
    arp_sender = SHP_live_networking.prepare_arp_sender(SHP_live_networking.STATIC_IP_CC)
    
    # start client
    start_shpclient(arp_sender, args.poi, args.reference, args.rtt, args.silence_poi, args.silence_cc, args.port, args.subnet, args.inputsource, args.deskew, args.bitlength, args.rounding_factor, args.subchanneling, args.subchanneling_bits, args.multihashing, args.ooodelivery, args.ecc, args.path_secret, args.savepcap)