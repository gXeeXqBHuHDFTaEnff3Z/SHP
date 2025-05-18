#!/usr/bin/env python3

import argparse
import socket
import time
import traceback
import scapy
from scapy.all import sniff, wrpcap
from scapy.layers.l2 import ARP
from scapy.config import conf
#conf.debug_dissector = 2 # debug full scapy error
import threading
import logging
import datetime
import os
import csv
import utils.SHP_algos as SHP_algos
import utils.SHP_ecc as SHP_ecc
import utils.SHP_live_networking as SHP_live_networking
import pandas as pd

STATIC_VERSION = '3.2'

# options
DEFAULT_POI     = 'broadcast_bpf'
DEFAULT_SILENCE = 2
DEFAULT_RTT     = 0
DEFAULT_INPUTSOURCE = 'ISD'
DEFAULT_SUBCHANNELING = 'none'
DEFAULT_SUB_BITS  = 0
DEFAULT_BITLENGTH = 3
DEFAULT_ROUNDING  = 0
DEFAULT_REHASHING = 2
DEFAULT_ECC       = 'none' # live ecc is still experimental
DEFAULT_SECRET = 'secret_message_received.txt'
DEFAULT_SAVEPCAP = False

# Get the absolute path of the current script
script_dir = os.path.dirname(os.path.abspath(__file__))

packet_pcap_file = os.path.join(script_dir, 'SHPserver.pcapng')  # pcap path to save packets to
timestamp_start = 0 # timestamp of START CC message
timestamp_fin = 0 # timestamp of START CC message
source_start = None # IP adress of the START source
last_packet_time = 0 # timestamp of the last packet (any type)
last_poi_time = 0 # timestamp of the last POI
last_cc_time = 0 # timestamp of the last CC POI
last_data_per_subchannel = {} # list of last data received per subchannel (for ISD, etc.)
list_last_data_pois = [] # list of POI between silence and timeout
counter_packets_received = 0 # sum of all packets observed
counter_poi_received = 0 # sum of poi observed
counter_cc_received = 0 # sum of CC POI observed
counter_cc_ignored_because_silence = 0 # sum of cc poi ignored because they came too soon after another CC
counter_cc_pointer_received = 0 # sum of pointer CC POI observed
counter_data_ignored_because_silence = 0 # sum of poi ignored because they came too soon after another
counter_data_ignored_because_timeout = 0 # sum of poi ignored because pointer came too late after data
counter_data_ecc_matches = 0 # sum of data poi received that had matching ecc
counter_watchdog_ecc_matches = 0 # sum of data poi received that had matching watchdog ecc
message_chunk = "" # data received so far for the message chunk (used for ecc=inline-hamming+)
message_received = '' # message received as readable string after completion
secret_bits = "" # data received and acceptes so far
stop_sniffing = False # used to stop the script

# Build the full path for the log file
log_file = os.path.join(script_dir, 'SHPserver.log')

# Configure logging for error tracking
logging.basicConfig(
    level=logging.DEBUG,
    format='%(levelname)s - %(message)s',
    #datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        #logging.FileHandler(log_file),  # Write to file
        logging.StreamHandler()         # Also write to console
    ]
)

# Check if pcap file exists; if not, create an empty one
if not os.path.exists(packet_pcap_file):
    open(packet_pcap_file, 'wb').close()  # Create an empty file if it doesn't exist

# Parse command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Packet capture and filtering based on POI, port, and subnet.")
    
    # arguments for poi filter
    parser.add_argument('--poi', type=str, default=DEFAULT_POI, help="Packet of interest type.") # all, port, subnet, broadcast_domain, broadcast_bpf
    parser.add_argument('--port', type=int, choices=range(0, 65536), default=443, help="Port number for POI (0-65535).")
    parser.add_argument('--subnet', type=str, default="10.0.0.0/8", help="Subnet for POI function (e.g., '192.168.1.0/24').")
    parser.add_argument('--silence_poi', type=args_check_silence, default=DEFAULT_SILENCE, help='Number of milliseconds any two PoI need to be apart (= phi or POI silence interval). Default 0 = disabled. Max 1000ms.')
    parser.add_argument('--silence_cc', type=args_check_silence, default=DEFAULT_SILENCE, help='Number of milliseconds any two CC messages need to be apart (= d or CC silence interval). Default 0 = disabled. Max 1000ms.')
    
    # arguments for SHP algorithm
    parser.add_argument('--inputsource', choices=['IPD', 'ISD', 'ISPN', 'ICD', 'timestamp', 'payload', 'tcp_seq'], default=DEFAULT_INPUTSOURCE, help='Defines source of the pointer data. Default=IPD.') # IPD=inter packet delay; ISD=inter signal delay; ISPN=inter signal packet number
    parser.add_argument('--deskew', choices=['none', 'sha3', 'md5', 'log', 'power'], default='sha3', help='Defines deskew transformation.')
    parser.add_argument('--rounding_factor', type=int, default=DEFAULT_ROUNDING, help='Rounding factor.')
    parser.add_argument('--bitlength', type=int, default=DEFAULT_BITLENGTH, help='Number of bits for hash and message comparison.') # basic chest length
    parser.add_argument('--subchanneling', choices=['none', 'baseipd', 'iphash', 'clock', 'clockhash'], default=DEFAULT_SUBCHANNELING, help='Defines how subchannel split is calculated.')
    parser.add_argument('--subchanneling_bits', type=int, default=DEFAULT_SUB_BITS, help='Number of bits used for multiplex subchannel number. Default=0')
    parser.add_argument('--ecc', choices=['none', 'hamming', 'hamming+', 'inline-hamming+'], default=DEFAULT_ECC, help='Type of error correction code. Allows matching near miss sequences. Default none.')
    parser.add_argument('--multihashing', type=int, default=DEFAULT_REHASHING, help='Number of bits used to mark how many hash iterations are needed to determine the message chunk. Default 0 = disabled. ')
    parser.add_argument('--ooodelivery', type=int, default=0, help='Number of bits used to mark the future message chunk, determining the number of future chunks to be checked. Default 0 = disabled. Maximum allowed value is 8.') # assumes CR supports packet reordering 
    
    parser.add_argument('--secret', type=str, default=DEFAULT_SECRET, help='File to write the secret message to.')

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
def capture_packets(arp_sender, poi, port, subnet, inputsource, deskew, bitlength, rounding_factor, subchanneling, subchanneling_bits, multihashing, ooodelivery, ecc, silence_poi, silence_cc, secret, savepcap):
    global stop_sniffing
    global timestamp_fin

    def packet_handler(packet):
        """Wrapper function to handle packet processing with error handling"""
        try:
            process_packet(arp_sender, packet, poi, port, subnet, inputsource, deskew, bitlength, rounding_factor,
                         subchanneling, subchanneling_bits, multihashing, ooodelivery, ecc, silence_poi, silence_cc, secret, savepcap)
        except scapy.error.Scapy_Exception as e:
            stacktrace = traceback.format_exc()
            logging.warning(f"Skipping malformed packet: {str(e)} with stacktrace {stacktrace}")
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
        timestamp_fin = time.time()
        stop_sniffing = True
    except socket.error as se:
        logging.error(f"Socket error during capture: {str(se)}")
        timestamp_fin = time.time()
        stop_sniffing = True
        time.sleep(1)
    except Exception as e:
        logging.error(f"Critical capture error: {str(e)}")
        timestamp_fin = time.time()
        stop_sniffing = True
    finally:
        # Cleanup code here if needed
        logging.info("Capture thread terminated")
 
# Process Packet: Filter and Log to File
def process_packet(arp_sender, packet, poi, port, subnet, inputsource, deskew, bitlength, rounding_factor, subchanneling, subchanneling_bits, multihashing, ooodelivery, ecc, silence_poi, silence_cc, secret, savepcap):
    global secret_bits
    global message_chunk
    global message_received # message as string after completion
    global last_packet_time
    global last_poi_time
    global last_cc_time
    global list_last_data_pois
    global last_data_per_subchannel
    global timestamp_start
    global timestamp_fin
    global source_start
    global counter_packets_received             # sum of all packets observed
    global counter_poi_received                 # sum of poi observed
    global counter_cc_received                  # sum of CC POI observed
    global counter_cc_ignored_because_silence    # sum of cc poi ignored because they came too soon after another CC
    global counter_cc_pointer_received          # sum of pointer CC POI observed
    global counter_data_ignored_because_silence  # sum of poi ignored because they came too soon after another
    global counter_data_ignored_because_timeout  # sum of poi ignored because pointer came too late after data
    global counter_data_ecc_matches             # sum of data poi received that had matching ecc
    global counter_watchdog_ecc_matches         # sum of data poi received that had matching watchdog ecc
    global stop_sniffing
    
    counter_packets_received += 1  # Increment counter packets received

    # default assumptions
    isCovert = False

    # Check if packet is POI. Might be CC or data channel.
    if (poi == 'broadcast_bpf') or (poi == 'all'):
        isPOI = True
    else:
        isPOI = SHP_algos.isPOI(packet, poi=poi, port=port, subnet=subnet, ignored=None)

    # ignore all non-POI
    if not isPOI:
        return
    
    # Write all poi packets to PCAPNG file and remember as POI
    if savepcap:
        write_packet_to_file(packet)

    # -> its a valid POI
    counter_poi_received += 1
    logging.debug(f'{packet.time} POI')
       
    # Check if packet is a covert channel message
    isCovert, bits3, bits4 = SHP_live_networking.is_covert_pointer(packet, SHP_live_networking.STATIC_IP_CC)
        
    # Handle covert channel signals
    if isCovert:
        counter_cc_received += 1
        #logging.info(f"Covert Channel Messsage: {packet.summary()}")

        # Handle CC FIN message
        if (bits4 == SHP_live_networking.STATIC_BITSTRING_STOP):
            stop_sniffing = True
            timestamp_fin = packet.time
            logging.info(f"{packet.time} Got covert channel FIN: {packet[ARP].pdst} with options [{bits3}:{bits4}]")

            # write message to file
            message_received = SHP_algos.write_secret_message(secret, secret_bits, source_start)
            return
        
        # If received in rappid succession, ignore other CC
        if (packet.time - last_cc_time) * 1000 < silence_cc:
            counter_cc_ignored_because_silence += 1
            logging.warning(f"{packet.time} CC Message in CC silence interval with options [{bits3}:{bits4}]")
            return
        
        # Handle CC START message
        elif (bits4 == SHP_live_networking.STATIC_BITSTRING_INIT):
            timestamp_start = packet.time
            source_start = packet[ARP].psrc  # Note down the source IP
            logging.info(f"Received covert channel START: {packet[ARP].pdst} with options [{bits3}:{bits4}]@{packet.time}")
            return
        
        # Ignore CC RETRY
        elif (bits4 == SHP_live_networking.STATIC_BITSTRING_RETRY):
            return
        
        # Handle data pointer
        if list_last_data_pois: # Check if list is non-empty
            # Handle data pointer with data to point to
            counter_cc_pointer_received += 1
            
            # Display data packet pointed to
            logging.debug(f"{packet.time} Pointer with options [{bits3}:{bits4}]]. Last POI@{list_last_data_pois[0].time}")

            # parse data from data channel packet
            source_data, secret_bits_new, subchannel, last_packet_time, last_data_per_subchannel, timestamp_start, ecc_match = SHP_algos.parse_datapacket(
                    list_last_data_pois[0], inputsource, deskew, bitlength, rounding_factor, subchanneling, subchanneling_bits, multihashing, int(bits3, 2),
                    ooodelivery, ecc, checksum_length, last_packet_time, last_data_per_subchannel, timestamp_start, message_chunk)
            
            if ecc_match:
                counter_data_ecc_matches += 1
            
            # verify data with watchdog checksum
            checksum_is = SHP_ecc.compute_checksum_6bit(secret_bits_new)
            checksum_should = SHP_ecc.compute_checksum_6bit(bits4[:6])

            # Handle experiment verification checksum fail
            if not (checksum_is == checksum_should):
             logging.warning(f"{packet.time} WATCHDOG MISMATCH | source:{source_data} -> msg:{secret_bits_new} | poi@{list_last_data_pois[0].time} | lastdata {last_data_per_subchannel} | is:{checksum_is} != should:{checksum_should} | CC pointer: {counter_cc_pointer_received}")
             SHP_live_networking.send_arp_request(arp_sender, checksum_should, SHP_live_networking.STATIC_BITSTRING_RETRY)     
             
             if (inputsource == 'ISPN'): 
                last_data_per_subchannel[subchannel] = 0
            
            else: # Watchdog Checksums check out, add to received message
                counter_watchdog_ecc_matches += 1
                secret_bits = secret_bits + secret_bits_new
                logging.info(f"{packet.time} Received data | source:{source_data} -> msg:{secret_bits_new} | poi@{list_last_data_pois[0].time} | msg length [{str(len(secret_bits))}]")
            
        # Handle no START, no FIN and we had no data packets to point to
        else:
            SHP_live_networking.send_arp_request(arp_sender, '00000000', SHP_live_networking.STATIC_BITSTRING_RETRY)
            logging.warning(f"{packet.time} No valid data POI seen before CC message with options {bits3}:{bits4}@{packet.time}).")
            counter_data_ignored_because_timeout += 1

        last_cc_time = packet.time

        return

    # -> its a data channel POI
    # observe poi silence and remove all data channel PoI within the silence timeframe
    count_poi_in_silence, _ = SHP_algos.flush_poi_list(packet, list_last_data_pois, silence_poi)
    counter_data_ignored_because_silence += count_poi_in_silence
    if (count_poi_in_silence > 0):
        logging.debug(f"{packet.time} {count_poi_in_silence} data POI in silence interval ({packet.time:.4f} - {last_poi_time:.4f} = {packet.time-last_poi_time:.4f}s < {silence_poi}ms). Skipped.")
        return

    # a POI that is not a pointer is a possible data packet for future pointers
    list_last_data_pois.insert(0, packet)
    last_poi_time = packet.time

    # a POI that is not a pointer is counter in the last_data
    if (inputsource == 'IPD'):
        subchannel = SHP_algos.get_subchannel(packet, subchanneling, subchanneling_bits, last_packet_time, rounding_factor)
        last_data_per_subchannel[subchannel] = packet.time

    elif (inputsource == 'ISPN'):
        subchannel = SHP_algos.get_subchannel(packet, subchanneling, subchanneling_bits, last_packet_time, rounding_factor)
        ispn_counter = last_data_per_subchannel.get(subchannel)
        ispn_counter = (ispn_counter + 1) if ispn_counter is not None else 1
        last_data_per_subchannel[subchannel] = ispn_counter

    return

# Write Packet to PCAPNG File
def write_packet_to_file(packet):
    try:
        wrpcap(packet_pcap_file, packet, append=True)  # Append packet to the PCAPNG file
    except Exception as e:
        logging.error("[ERROR] writing packet to PCAPNG file: %s", e)

def filter_charmap_invalid_chars(text):
    return ''.join(char for char in text if char.encode('charmap', errors='ignore') == char.encode('charmap', errors='strict'))

def write_statistics_to_csv(poi, inputsource, bitlength, rounding_factor, multihashing, ecc):
    """
    Write capture statistics to a CSV file (stats_server.csv).
    Creates the file with headers if it doesn't exist.
    Appends a new row with current statistics if the file exists.
    """
  
    # Define the CSV file name
    current_script_path = os.path.realpath(__file__)
    script_dir = os.path.dirname(current_script_path)
    csv_filename = os.path.join(script_dir, 'stats_server.csv')
    
    # prepare data
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    duration_connection = (timestamp_fin - timestamp_start) if timestamp_fin > 0 else -1
    parameters = f'{poi}:{inputsource}:{bitlength}b:{rounding_factor}r:{multihashing}m:{ecc}'
    caf = (bitlength / multihashing) if multihashing > 0 else bitlength # CAF
    avgdistance_all = (counter_packets_received / counter_cc_pointer_received) if counter_cc_pointer_received > 0 else -1 # average matching distance measured against all traffic
    avgdistance_poi = (counter_poi_received / counter_cc_pointer_received) if counter_cc_pointer_received > 0 else -1 # average matching distance measured against all traffic
    mps = round(counter_watchdog_ecc_matches / duration_connection, 4) if duration_connection > 0 else -1
    bps = round(len(secret_bits) / duration_connection, 4) if duration_connection > 0 else -1
    steganographic_bandwidth = (bitlength / avgdistance_all) if avgdistance_all != 0 else -1 # steganographic bandwidth: bits transmitted / average distance between matches
    watchdog_hitrate = counter_watchdog_ecc_matches / counter_cc_pointer_received if counter_cc_pointer_received > 0 else 0 # percentage of watchdog matches
    fitness = bps * watchdog_hitrate if caf > 1.0 else 0.0
    comment = f'Version {STATIC_VERSION}'

    stats = {
        'parameters': parameters,
        'FITNESS': fitness,
        'bps': bps,
        'mps': mps,
        'caf': caf,
        'sbw': steganographic_bandwidth,
        'avgdistance_all': avgdistance_all,
        'avgdistance_poi': avgdistance_poi,
        'watchdog_hitrate': watchdog_hitrate,
        'count_packets_rec': counter_packets_received,
        'count_poi_rec': counter_poi_received,
        'count_cc_rec': counter_cc_received,
        'count_cc_ignored_in_silence': counter_cc_ignored_because_silence,
        'count_cc_pointer_rec': counter_cc_pointer_received,
        'count_data_ignored_in_silence': counter_data_ignored_because_silence,
        'count_data_ignored_in_timeoput': counter_data_ignored_because_timeout,
        'count_data_ecc_matches': counter_data_ecc_matches,
        'count_watchdog_ecc_matches': counter_watchdog_ecc_matches,
        'secret_bits_count': len(secret_bits),
        'timestamp_start': timestamp_start,
        'timestamp_stop': current_time,
        'duration_seconds': duration_connection,
        'source_ip': source_start,
        'comment': comment
    }

    try:
        file_exists = False
        try:
            with open(csv_filename, mode='r') as file:
                file_exists = True
        except FileNotFoundError:
            pass
    
        with open(csv_filename, mode='a', newline='') as file:
            writer = csv.writer(file, delimiter=',')
            if not file_exists:
                writer.writerow(stats.keys())  # Write headers only if file does not exist
            writer.writerow(stats.values())  # Write values

       # Display key stats
        print(f'FITNESS: {fitness} | watchdog hitrate: {watchdog_hitrate}')
        print(f'bps / mps / CAF: {bps} / {mps} / {caf}')
        print(f'distance all /poi: {avgdistance_all} / {avgdistance_poi}')
        print(f'ECC total / shpecc / watchdog: {counter_cc_pointer_received} / {counter_data_ecc_matches} / {counter_watchdog_ecc_matches}')

        logging.info(f"Statistics written to {csv_filename}")
        return csv_filename
        
    except Exception as e:
        logging.error(f"Failed to write statistics to CSV: {e}")
 
import os
import pandas as pd

def open_csv_in_excel(csv_file):
    """
    Converts a CSV file to an Excel file and opens it in Excel.
    Catches and prints messages for common exceptions.
    
    :param csv_file: Path to the CSV file.
    """
    try:
        # Attempt to read the CSV file
        df = pd.read_csv(csv_file, delimiter=";")  # Adjust delimiter if needed

        # Create the corresponding Excel filename
        excel_file = csv_file.replace(".csv", ".xlsx")

        # Write to Excel
        df.to_excel(excel_file, index=False, engine="openpyxl")

        # Attempt to open the Excel file
        os.startfile(excel_file)
        print(f"Converted and opened: {excel_file}")
    
    except FileNotFoundError:
        print(f"Error: The file '{csv_file}' does not exist.")
    except pd.errors.EmptyDataError:
        print(f"Error: The file '{csv_file}' is empty.")
    except pd.errors.ParserError:
        print(f"Error: There was a problem parsing the CSV file '{csv_file}'.")
    except PermissionError:
        print(f"Error: Permission denied when trying to open or write to '{csv_file}'.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


# Start Packet Capture in a Thread
def start_shpserver(arp_sender, poi, port, subnet, inputsource, deskew, bitlength, rounding_factor, subchanneling, subchanneling_bits, multihashing, ooodelivery, ecc, silence_poi, silence_cc, secret, savepcap):
    global stop_sniffing
    global packet_pcap_file

    # save packets to a pcap named after the options
    safe_timestamp = datetime.datetime.now().isoformat().replace(":", "-").replace(" ", "_")
    packet_pcap_file = os.path.join(script_dir, f'{safe_timestamp}-SHPserver-{poi}-{inputsource}-{bitlength}b-{rounding_factor}r-{multihashing}m-{subchanneling}_{subchanneling_bits}s-{ecc}.pcapng') 

    try:
        logging.info(f"Starting SHPserver (= covert receiver) with parameters: poi={poi}, inputsource={inputsource}, bitlength={bitlength}, rounding={rounding_factor}, multihashing={multihashing}, ecc={ecc}, savepcap={savepcap}")
        
        # Start capture in a separate thread
        capture_thread = threading.Thread(
            target=capture_packets,
            args=(arp_sender, poi, port, subnet, inputsource, deskew, bitlength, rounding_factor, 
                  subchanneling, subchanneling_bits, multihashing, ooodelivery, ecc, 
                  silence_poi, silence_cc, secret, savepcap),
            name="PacketCaptureThread"
        )
        capture_thread.daemon = True

        # Start and monitor the capture thread
        capture_thread.start()
        while capture_thread.is_alive():
            capture_thread.join(timeout=1.0)
            if stop_sniffing:
                logging.info(f"Told to stop sniffing...")
                break

    except KeyboardInterrupt:
        logging.info(f"Received keyboard shutdown signal, stopping capture...")
        stop_sniffing = True
        capture_thread.join(timeout=5.0)  # Give thread time to cleanup
        
    except Exception as e:
        logging.error(f"Failed to start SHPserver: {str(e)}")
        raise
    finally:
        if 'capture_thread' in locals() and capture_thread.is_alive():
            logging.warning("Capture thread did not terminate cleanly")

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

    # check ecc parameter and calc ecc length
    global checksum_length
    checksum_length = SHP_ecc.get_checksum_length(args.ecc, args.bitlength)

    # save received message to current dir
    current_script_path = os.path.realpath(__file__)
    script_dir = os.path.dirname(current_script_path)
    args.secret = os.path.join(script_dir, args.secret)

    # prepare our sockets
    arp_sender = SHP_live_networking.prepare_arp_sender(SHP_live_networking.STATIC_IP_CC)

    start_shpserver(arp_sender, args.poi, args.port, args.subnet, args.inputsource, args.deskew, args.bitlength, args.rounding_factor, args.subchanneling, args.subchanneling_bits, args.multihashing, args.ooodelivery, args.ecc, args.silence_poi, args.silence_cc, args.secret, args.savepcap)
    
    print("\nCapture stopped.")
   
    csv_filename = write_statistics_to_csv(args.poi, args.inputsource, args.bitlength, args.rounding_factor, args.multihashing, args.ecc)
    #open_csv_in_excel(csv_filename)