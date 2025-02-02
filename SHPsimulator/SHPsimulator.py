from scapy.all import PcapReader, Ether, IP, IPv6, TCP, UDP, ARP
from scapy.utils import PcapWriter
import csv
import argparse
import logging
import logging.handlers as loghandlers
import random
import copy
import traceback # for the logging function
from datetime import datetime, date
import os# for file ops
import glob
from scipy.stats import boxcox # for demux
import numpy as np
from numpy import log1p, power # for demux
import SHP_ecc # our ECC module
import SHP_algos # our SHP algorithms

def setup_logger():
    """
    Sets up a logger for error logging.

    Returns:
    - logging.Logger: The configured logger.
    """
    # Create a logger object
    logger = logging.getLogger('SHPsimulatorLogger')

    if not logger.handlers:  # Check if handlers already exist
        logger.setLevel(logging.INFO)  # Set the logger to capture error, warning, info level messages
    
        # Create file handler which logs error messages
        fh = loghandlers.RotatingFileHandler(
            'SHPsimulator.log',     # Name of the log file
            maxBytes=1024*1024*5,   # Log file size limit (5MB)
            backupCount=5           # Number of backup files to keep
        )
        fh.setLevel(logging.INFO)
        
        # Create console handler for output up to INFO level
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
    
        # Create formatter and add it to the handlers
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
    
        # Add the handlers to the logger
        logger.addHandler(fh)
        logger.addHandler(console_handler)
    
    return logger

# Instantiate the logger
logger = setup_logger()

def log_error(info, exception, packet=None):
    """
    Logs an error with traceback.

    Parameters:
    - exception (Exception): The exception to log.
    - packet (Scapy): The PDU that was currently being parsed
    """
    # Log the exception with traceback
    if (packet) is not None:
        logger.error(f'{info} while parsing PDU {packet.summary()}', exc_info=True)
    else:
        logger.error(info, exc_info=True)
  
def process_packet_batch(batch, writer, poi, port, inputsource, deskew, subchanneling, subchanneling_bits, first_timestamp, last_packet_time, rounding_factor, subnet, secret_message, index, bitlength, last_poi_time, match_number, match_cycle, multihashing, ooodelivery, send_chunks, last_data_per_subchannel, ecc, checksum_length, packetloss_percentage, packetdelay, packetjitter, pointer_template, verbose):
    """
    Processes a batch of packets using the existing `process_packet` method.

    Args:
        batch (list): List of packets to process in this batch.
        writer (csv.DictWriter): CSV writer to record the output.
        <other args> Same as `process_packet` method.
    Returns:
        index, last_packet_time, match_number, match_cycle, send_chunks, last_data_per_subchannel
    """
    for pkt in batch:
        index, last_packet_time, counter_poi, match_number, match_cycle, send_chunks, last_data_per_subchannel, cr_received_pdus, cr_correctly_matched_pdus = process_packet(
            pkt, writer, poi, port, inputsource, deskew, subchanneling, subchanneling_bits, first_timestamp, last_packet_time, rounding_factor, subnet,
            secret_message, index, bitlength, last_poi_time, counter_poi, match_number, match_cycle, cr_received_pdus, cr_correctly_matched_pdus, multihashing, ooodelivery, send_chunks,
            last_data_per_subchannel, ecc, checksum_length, packetloss_percentage, packetdelay, packetjitter, verbose 
        )

    return index, last_packet_time, counter_poi, match_number, match_cycle, send_chunks, last_data_per_subchannel
    
def process_packet(pkt, pcap_writer, writer, poi, port, inputsource, deskew, subchanneling, subchanneling_bits, first_timestamp, last_packet_time, last_poi_time, rounding_factor, subnet, secret_message, index, bitlength, counter_poi, match_number, match_cycle, cr_received_pdus, cr_correctly_matched_pdus, multihashing, ooodelivery, send_chunks, last_data_per_subchannel, ecc, checksum_length, packetloss_percentage, packetdelay, delayAdjustmentTerm, packetjitter, silence, simulateCR, saveWithPointer, pointer_template, verbose):
    """Processes each packet, calculating IPD based on the last packet of interest."""

    try:
        match = False
        
        # Default values for per-PDU indicies
        multihashing_index = 0
        checking_index = 0
        
        # check if poi
        packet_interest = SHP_algos.isPOI(pkt, poi, port, subnet)

        # check if phi silence interval for PoI was observed 
        if (packet_interest) and (silence > 0) and (last_poi_time > 0):
            this_timestamp = pkt.time
            toosoon = ((this_timestamp - last_poi_time) * 1000) <= silence
            if toosoon:
                packet_interest = False 

            last_poi_time = this_timestamp

        if packet_interest:
            # count pois
            counter_poi = counter_poi + 1
            
            # Calculate subchannel if mux is used; Default=0
            subchannel = SHP_algos.get_subchannel(pkt, subchanneling, subchanneling_bits, last_packet_time, rounding_factor)
            
            # if we count packets per subchannel, increment now
            if (inputsource == 'ISPN'):
                ispn_counter = last_data_per_subchannel.get(subchannel)
                ispn_counter = (ispn_counter + 1) if ispn_counter is not None else 0
                last_data_per_subchannel[subchannel] = ispn_counter
            
            # Calculate source_data per current subchannel
            source_data = SHP_algos.get_source_data(pkt, inputsource, subchannel, last_data_per_subchannel, first_timestamp)
                
            # round source data if applicable
            if inputsource in ('IPD', 'ISD', 'ICD', 'timestamp'):
                source_data = round(source_data, rounding_factor)
        
            # Apply deskewing transformation
            deskewed_bits = SHP_algos.apply_deskew(source_data, deskew, bitlength + checksum_length)
            
            # go through message chunks to be send and check if we have a match
            msg_chunk_range = 2 ** ooodelivery if (ooodelivery > 0) else 1
            for message_chunk in range(msg_chunk_range):
                checking_index = index + message_chunk % (len(secret_message) * 8 // bitlength) # index to check is relative to the message
                
                # Skip this message chunk if it has already been succesfully send
                if (ooodelivery > 0) and (checking_index in send_chunks):
                    continue
                    
                # convert message to bits TODO: only once
                secret_message_bitstring = ''.join(format(ord(c), '08b') for c in secret_message)

                # get current message bits
                message_bits = SHP_algos.extract_message_bits(secret_message_bitstring, checking_index, bitlength, ecc)
                
                # using multihashing means we always use SHA3 after the first check
                if (multihashing != 0):
                    current_hash, _ = SHP_algos.sha3_hash_bits(source_data, bitlength + checksum_length)
                
                for i in range(0, 2 ** multihashing):
                    # --- check if we have a match ---
                    
                    if (ecc == 'none') or (ecc == 'inline-hamming+'): # check for exact raw match
                        match, message_bits, deskewed_bits = SHP_algos.compare_bits(message_bits, deskewed_bits)
                    elif (ecc == 'hamming'): # check for exact match including checksum
                        message_with_ecc_bits = SHP_ecc.checksum(message_bits, ecc)
                        match, message_with_ecc_bits, deskewed_bits = SHP_algos.compare_bits(message_with_ecc_bits, deskewed_bits)                        
                    elif (ecc == 'hamming+'): # check for match with tolerant checksum
                        message_with_ecc_bits = SHP_ecc.checksum(message_bits, ecc)
                        match, message_with_ecc_bits, deskewed_bits = SHP_algos.compare_bits_ext(message_with_ecc_bits, deskewed_bits, 1)
                                        
                    # if we have a match, we progress through the message
                    if match:
                        
                        # increase match counter
                        match_number += 1
                        
                        if (inputsource == 'ISD'): # if we use inter signal timing, NOW is a signal
                            last_data_per_subchannel[subchannel] = pkt.time
                        elif (inputsource == 'ISPN'): # if we use signal distance, distance is now 0
                            last_data_per_subchannel[subchannel] = 0
                            
                        if (ooodelivery <= 0):
                            index = (index + 1) % (len(secret_message) * 8 // bitlength)
                        else:
                            # add send message chunk to list of send chunks
                            send_chunks.add(checking_index)
                            # update first message chunk to be send. skip multiple indicies if already send. 
                            if (checking_index == index):
                                while index in send_chunks:
                                    index = (index + 1) % (len(secret_message) * 8 // bitlength)
                                    if (index == 0):
                                        break
                    
                        # BUG: when using ooop we can roll over before even moving on. match cycle will rise steep and then stagnate? debug the list of matches
                        # if we are through the message, start from the beginning
                        if (index == 0):
                            match_cycle += 1
                            send_chunks = set()
                            
                        # -- write pointer to file 
                        if (saveWithPointer):
                            # Copy the ARP template and update the timestamp
                            pointer_request = pointer_template.copy()
                            pointer_request.time = pkt.time 
                    
                            # Write the ARP request to the output file
                            pcap_writer.write(pointer_request)
                        
                            
                        if (simulateCR):
                            # -- count correct receptions by CR using the given robustness variables ---
                            # (1) Determine if the current packet and its pointer are received
                            current_packet_received = random.uniform(0, 100) >= packetloss_percentage
                            pointer_packet_received = random.uniform(0, 100) >= packetloss_percentage

                            # (2) We count received if the packet is received and its pointer
                            if current_packet_received and pointer_packet_received:
                                cr_received_pdus = cr_received_pdus + 1

                            # (3) Determine if the packet pointed to matches with the same information the CS wanted to send
                            #   (a) determine if jitter impacts this packet by picking a random jitter, applying it to the timestamp and seeing if we get the same match
                            #       i. pick random jitter and apply to timestamp
                                current_jitter = np.random.normal(loc=0, scale=packetjitter)
                                cr_last_packet_time = pkt.time + packetdelay - delayAdjustmentTerm + (current_jitter / 1000)
                                cr_pkt = copy.deepcopy(pkt)
                                cr_pkt.time = cr_last_packet_time
                      
                                #       i. Calculate CR source_data per current subchannel
                                cr_source_data = SHP_algos.get_source_data(cr_pkt, inputsource, subchannel, last_data_per_subchannel, first_timestamp)
                        
                                #       ii. round source data if applicable
                                if inputsource in ('IPD', 'ISD', 'ICD', 'timestamp'):
                                    cr_source_data = round(cr_source_data, rounding_factor)
                            
                            #       iii. Apply CR deskewing transformation
                                cr_deskewed_bits = SHP_algos.apply_deskew(cr_source_data, deskew, bitlength + checksum_length)
                            
                            #       iv. Check for CR match
                            #       BUG: This does not yet support multihashing
                                if (ecc == 'none') or (ecc == 'inline-hamming+'): # check for exact raw match
                                    cr_match, cr_message_bits, _ = SHP_algos.compare_bits(message_bits, cr_deskewed_bits)
                                elif (ecc == 'hamming'): # check for exact match including checksum
                                    message_with_ecc_bits = SHP_ecc.checksum(message_bits, ecc)
                                    cr_match, cr_message_with_ecc_bits, _ = SHP_algos.compare_bits(message_with_ecc_bits, cr_deskewed_bits)                        
                                elif (ecc == 'hamming+'): # check for match with tolerant checksum
                                    message_with_ecc_bits = SHP_ecc.checksum(message_bits, ecc)
                                    cr_match, cr_message_with_ecc_bits, _ = SHP_algos.compare_bits_ext(message_with_ecc_bits, cr_deskewed_bits, 1) 
                           
                            #   (b) if all conditions are met, we get a good match
                                cr_correctly_matched = (pointer_packet_received) and (current_packet_received) and (cr_match)
                                if cr_correctly_matched:
                                    cr_correctly_matched_pdus = cr_correctly_matched_pdus + 1
                            
                            else: # if not CR received PDU
                                cr_last_packet_time = None  # Packet was lost, so no reception time
                        
                            # (4) if we had a match but the pointer was not received, we will get a checksum mismatch next packet, so both are lost
                            if not pointer_packet_received:
                                cr_correctly_matched_pdus = cr_correctly_matched_pdus - 1

                            break  # Stop checking further CS message chunks if a match is found.
                    
                    # if no match then next multihashing
                    if (multihashing != 0):
                        deskewed_bits, current_hash = SHP_algos.sha3_hash_bits(current_hash, bitlength + checksum_length)
 
            # write details csv
            # hint: if enabled, this costs 4x performance!
            if (verbose):
                writer.writerow({
                    'source': source_data, 'subchannel': subchannel, 'deskewed_bits': deskewed_bits, 'message_bits': message_bits, 
                    'match': match, 'match_cycle': match_cycle, 'checking_index': checking_index, 'multihashing': multihashing_index, 
                    'cr_received': cr_received_pdus, 'cr_matches': cr_correctly_matched_pdus
                })
                
            # update last data according to source; this was a POI
            if (inputsource == 'IPD'):     
                last_data_per_subchannel[subchannel] = pkt.time  # last data is this PDUs time

            return index, pkt.time, last_poi_time, counter_poi, match_number, match_cycle, send_chunks, last_data_per_subchannel, cr_received_pdus, cr_correctly_matched_pdus # Return the current packet time to update the last packet of interest time
    
    except Exception as e:
        # Initialize fallback values for logging or provide alternative logic
        message_bits = locals().get('message_bits', 'N/A')
        deskewed_bits = locals().get('deskewed_bits', 'N/A')
        index = locals().get('index', 'N/A')
        checksum_length = locals().get('checksum_length', 'N/A')
        
        # if we get an unhandled exception for a PDU we stop this script
        log_error(f'Exception while checking PDU with values msg_bits {message_bits}, deskewed_bits {deskewed_bits}, index {index}, checksum_length {checksum_length}', e, pkt)
        exit(2607)
        
    return index, last_packet_time, counter_poi, match_number, match_cycle, send_chunks, last_data_per_subchannel, cr_received_pdus, cr_correctly_matched_pdus # Return the last packet of interest time unchanged if the current packet does not meet criteria

def process_pcap_files(pcap_files, capfolder, subnet, poi, inputsource, deskew, subchanneling, subchanneling_bits, output_folder, secret_file, rounding_factor, bitlength, multihashing, ooodelivery, ecc, checksum_length, comment_field, batching, packetloss_percentage, packetdelay, delayAdjustmentTerm, packetjitter, silence, simulateCR, saveWithPointer, verbose, port=None):
    # init variables
    secret_message = SHP_algos.read_secret_message(secret_file)
    pointer_template = None
    if saveWithPointer:
        pointer_template = SHP_algos.create_pointer('1.2.3.4', 'AA:AA:AA:AA:AA:AA', '4.3.2.1')  # Placeholder for the ARP request template
    
    # Initialize counters
    script_runtime_start = datetime.now()
    total_bytes_processed = 0
    total_pdus_processed = 0

    counter_poi = 0
    match_number = 0
    match_cycle = 0  
    send_chunks = set() # set of secret message chunks that have already been sent
    last_packet_time = None
    last_poi_time = None
    last_data_per_subchannel = {}
    total_captured_time = 0
    cr_received_pdus = 0
    cr_last_packet_time = None
    cr_correctly_matched_pdus = 0
    
    # MAIN PACKET PROCESSING
    if (batching == True):
        total_bytes_processed, total_pdus_processed, counter_poi, match_number, match_cycle, send_chunks, last_packet_time, last_poi_time, last_data_per_subchannel, total_captured_time, cr_received_pdus, cr_correctly_matched_pdus = process_pcap_files_in_batches(pcap_files, capfolder, subnet, poi, inputsource, deskew, subchanneling, subchanneling_bits, output_folder, secret_file, rounding_factor, bitlength, multihashing, ooodelivery, ecc, checksum_length, comment_field, secret_message, total_bytes_processed, total_pdus_processed, counter_poi, match_number, match_cycle, send_chunks, last_packet_time, last_poi_time, last_data_per_subchannel, total_captured_time, packetloss_percentage, packetdelay, delayAdjustmentTerm, packetjitter, cr_received_pdus, cr_correctly_matched_pdus, silence, simulateCR, saveWithPointer, pointer_template, verbose, port)
    else:    
        total_bytes_processed, total_pdus_processed, counter_poi, match_number, match_cycle, send_chunks, last_packet_time, last_poi_time, last_data_per_subchannel, total_captured_time, cr_received_pdus, cr_correctly_matched_pdus = process_pcap_files_by_iteration(pcap_files, capfolder, subnet, poi, inputsource, deskew, subchanneling, subchanneling_bits, output_folder, secret_file, rounding_factor, bitlength, multihashing, ooodelivery, ecc, checksum_length, comment_field, secret_message, total_bytes_processed, total_pdus_processed, counter_poi, match_number, match_cycle, send_chunks, last_packet_time, last_poi_time, last_data_per_subchannel, total_captured_time, packetloss_percentage, packetdelay, delayAdjustmentTerm, packetjitter, cr_received_pdus, cr_correctly_matched_pdus, silence, simulateCR, saveWithPointer, pointer_template, verbose, port)

    ### CALCULATE SUMMARY VALUES ###
    # file and timestamps
    summary_file_name = output_folder + 'SHPsim_summary.csv'
    current_date = date.today() # date of simulation
    current_time = datetime.now().strftime("%H:%M:%S") # time of simulation
    # script runtime
    script_runtime = (datetime.now() - script_runtime_start)
    total_seconds = int(script_runtime.total_seconds())
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    script_runtime = f"{hours}:{minutes:02}:{seconds:02}"
    
    # LRU cache hitrate
    cache_info = SHP_algos.apply_deskew.cache_info()
    cache_uses = (cache_info.hits + cache_info.misses)
    cache_hitrate = (cache_info.hits / cache_uses) if (cache_uses > 0) else 0
    cache_hitrate = f'{cache_hitrate:.2%}'

    # processing stats
    gb_processed = round ( total_bytes_processed / (1024 ** 3) , 2 ) # GByte of captures traffic processed
    pdus_processed = total_pdus_processed # number of traffic PDUs processed
    
    # Calculate the average base bandwidth in bps
    if total_captured_time > 0:
        base_bandwidth_bps = (total_bytes_processed * 8) // total_captured_time # Convert bytes to bits
    else:
        base_bandwidth_bps = 0
    
    if (poi != 'port'):
        port = '-'
             
    # scientific results
    bits_for_one_pointer = (ooodelivery + multihashing) # number of bits needed for one signal. note: Muxing does not cost extra bits!
    if bits_for_one_pointer < 1: # if we just need to send any signal, we count this as one bit
        bits_for_one_pointer = 1
    
    cr_matched_by_received = cr_correctly_matched_pdus / cr_received_pdus if cr_received_pdus != 0 else 0 # CR percent of correct matches in the received PDUs
    ratio_matches_per_second = round ((match_number / total_captured_time), 4) if (total_captured_time != 0) else 0 # matches per second (= pointers per second)
    bandwidth = round( (match_number * bitlength) / total_captured_time, 4) if total_captured_time != 0 else 0 # bandwidth in bps
    bandwidth_by_base = round(bandwidth / base_bandwidth_bps,6) if base_bandwidth_bps != 0 else 0 # covert bandwidth / base bandwidth
    total_effective_bits = (match_number * bitlength) # secret bits effectively transmitted
    total_pointer_bits = (match_number * bits_for_one_pointer) # total number of bits needed as pointer OR number of bits on CC wire
    ratio_subchannel_bits_by_covert_bits = round(total_effective_bits / total_pointer_bits,2) if total_pointer_bits != 0 else 0 # meant b / said b OR covert amplification factor (CAF)
    ratio_total_pdus_by_matches = round(total_pdus_processed / match_number, 2) if match_number != 0 else 0 # avg. signal distance
    ratio_meantb_by_distance = round ((bitlength / ratio_total_pdus_by_matches), 4) if ratio_total_pdus_by_matches != 0 else 0 # steganographic bandwidth
    
    # collect summary values
    summary_data = [current_date, current_time, script_runtime, cache_hitrate, gb_processed, pdus_processed, base_bandwidth_bps, total_captured_time, 
                os.path.basename(capfolder), inputsource, poi, subnet, port, bitlength, rounding_factor, subchanneling, subchanneling_bits, ecc, multihashing, ooodelivery, deskew, 
                packetloss_percentage, packetdelay, packetjitter,
                counter_poi, match_number, match_cycle, 
                cr_received_pdus, cr_correctly_matched_pdus, cr_matched_by_received,
                ratio_matches_per_second, bandwidth, bandwidth_by_base, ratio_meantb_by_distance, total_effective_bits, ratio_subchannel_bits_by_covert_bits, ratio_total_pdus_by_matches,
                comment_field]
                
    # write summary csv
    try:
        with open(summary_file_name, 'a', newline='') as file:
            writer = csv.writer(file)
            # Check if file is empty by getting to the first byte
            file.seek(0, 2)
            if file.tell() == 0:
                writer.writerow(['date', 'time', 'runtime', 'cache hitrate', 'GB processed', 'PDUs processed', 'base bps' , 'Total Time in PCAPs', 
                             'capfolder', 'source', 'poi', 'subnet', 'port', 'bitlength', 'rounding', 'subchanneling', 'subchanneling_bits', 'ecc', 'multihashing', 'oood', 'deskew', 
                             'cr_pktloss', 'cr_delay', 'cr_jitter',
                             '# POI', '# MATCHES', 'MATCH CYCLES', 'CR_RECEIVED', 'CR_MATCHES', 'CRM%', 'MATCHPS', 'BPS', 'BPS%', 'STEG BANDWIDTH', 'B ON WIRE', 'CAF', 'DISTANCE', 'Comment'])
            writer.writerow(summary_data)
    except Exception as e:
        log_error(f"Failed to write to {summary_file_name}", e)
    
    logger.info(f"Processing completed. Results have been written to {summary_file_name}")
    
def process_pcap_files_by_iteration(pcap_files, capfolder, subnet, poi, inputsource, deskew, subchanneling, subchanneling_bits, output_folder, secret_file, rounding_factor, bitlength, multihashing, ooodelivery, ecc, checksum_length, comment_field, secret_message, total_bytes_processed, total_pdus_processed, counter_poi, match_number, match_cycle, send_chunks, last_packet_time, last_poi_time, last_data_per_subchannel, total_captured_time, packetloss_percentage, packetdelay, delayAdjustmentTerm, packetjitter, cr_received_pdus, cr_correctly_matched_pdus, silence, simulateCR, saveWithPointer, pointer_template, verbose, port=None):

    # write details csv by iterating through pcaps
    details_file_name = f'{output_folder}source_{inputsource}__poi_{poi}__port_{str(port)}__bitl_{str(bitlength)}__round_{str(rounding_factor)}__subchanneling_{subchanneling}__subchanneling_bits_{str(subchanneling_bits)}__ecc_{ecc}__multiptr_{str(multihashing)}__oood_{str(ooodelivery)}.csv'
    with open(details_file_name, mode='w', newline='') as csv_file:
        fieldnames = ['source', 'subchannel', 'deskewed_bits', 'message_bits', 'match', 'match_cycle', 'checking_index', 'multihashing', 'cr_received', 'cr_matches']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        last_seen_time = None
        message_index = 0

        for pcap_file in pcap_files:
            logger.info(f"Processing {os.path.basename(pcap_file)}...")
            
            # init timestamp counters
            first_timestamp = float('inf')  # Initialize with max value
            last_timestamp = 0  # Initialize with zero
            
            # prepare pcap with pointer writing
            output_pcap_file = os.path.join('.', 'pcap-ADDEDPOINTERS', os.path.basename(pcap_file))
            # Make sure the directory exists:
            os.makedirs(os.path.dirname(output_pcap_file), exist_ok=True)
            
            # go through all pcaps and there each PDU
            with PcapReader(pcap_file) as pcap_reader, PcapWriter(output_pcap_file, append=False, sync=True) as pcap_writer:
                for pkt in pcap_reader:
                
                    # update counters
                    total_bytes_processed += len(pkt)
                    total_pdus_processed += 1
                    
                    # Display progress every once in a while
                    if total_pdus_processed % 5000000 == 0:
                        logger.info(f"SHPsimulator for {comment_field}: {str(total_pdus_processed // 1000000)}mio PDUs done, so far {str(match_number)} matches.")
            
                    # Update the earliest and latest timestamps
                    if pkt.time < first_timestamp:
                        first_timestamp = pkt.time
                    if pkt.time > last_timestamp:
                        last_timestamp = pkt.time
                        
                    # if we are writing the PCAP out with pointer, add the current overt packet
                    if saveWithPointer:
                        pcap_writer.write(pkt)
                        
                    # process individual packet
                    message_index, last_packet_time, last_poi_time, counter_poi, match_number, match_cycle, send_chunks, last_data_per_subchannel, cr_received_pdus, cr_correctly_matched_pdus = process_packet(
                        pkt, pcap_writer, writer, poi, port, inputsource, deskew, subchanneling, subchanneling_bits, first_timestamp, last_packet_time, last_poi_time,
                        rounding_factor, subnet, secret_message, message_index, bitlength, counter_poi, match_number, match_cycle, cr_received_pdus, cr_correctly_matched_pdus, 
                        multihashing, ooodelivery, 
                        send_chunks, last_data_per_subchannel, ecc, checksum_length, packetloss_percentage, packetdelay, delayAdjustmentTerm, packetjitter, 
                        silence, simulateCR, saveWithPointer, pointer_template, verbose
                    )
                        
            # Calculate time elapsed during this pcap file and add it
            time_elapsed_in_file = last_timestamp - first_timestamp if first_timestamp < float('inf') else 0
            total_captured_time += time_elapsed_in_file
                        
    return total_bytes_processed, total_pdus_processed, counter_poi, match_number, match_cycle, send_chunks, last_packet_time, last_poi_time, last_data_per_subchannel, total_captured_time, cr_received_pdus, cr_correctly_matched_pdus

def process_pcap_files_in_batches(pcap_files, capfolder, subnet, poi, inputsource, deskew, subchanneling, subchanneling_bits, output_folder, secret_file, rounding_factor, bitlength, multihashing, ooodelivery, ecc, checksum_length, comment_field, secret_message, total_bytes_processed, total_pdus_processed, counter_poi, match_number, match_cycle, send_chunks, last_packet_time, last_data_per_subchannel, total_captured_time, packetloss_percentage, packetdelay, delayAdjustmentTerm, packetjitter, silence, saveWithPointer, pointer_template, verbose, port=None):

    # Write details CSV
    details_file_name = f'{output_folder}batched_source_{inputsource}__poi_{poi}__port_{str(port)}__bitl_{str(bitlength)}__round_{str(rounding_factor)}__subchanneling_{subchanneling}__subchanneling_bits_{str(subchanneling_bits)}__ecc_{ecc}__multiptr_{str(multihashing)}__oood_{str(ooodelivery)}.csv'
    with open(details_file_name, mode='w', newline='') as csv_file:
        fieldnames = ['source', 'subchannel', 'deskewed_bits', 'message_bits', 'match', 'match_cycle', 'checking_index', 'multihashing']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        last_poi_time = None
        last_seen_time = None
        message_index = 0

        for pcap_file in pcap_files:
            logger.info(f"Processing {os.path.basename(pcap_file)}...")
            
            # Init timestamp counters
            first_timestamp = float('inf')  # Initialize with max value
            last_timestamp = 0  # Initialize with zero
            
            # Read batches of packets
            with PcapReader(pcap_file) as pcap_reader:
                batch = []
                for pkt in pcap_reader:
                
                    # Update the earliest and latest timestamps
                    if pkt.time < first_timestamp:
                        first_timestamp = pkt.time
                    if pkt.time > last_timestamp:
                        last_timestamp = pkt.time
                        
                    # Assert that last_data_per_subchannel is a dictionary
                    assert isinstance(last_data_per_subchannel, dict), "last_data_per_subchannel must be a dictionary."
                        
                    batch.append(pkt)
                    if len(batch) >= MAX_BATCH_SIZE:
                        message_index, last_packet_time, counter_poi, match_number, match_cycle, send_chunks, last_data_per_subchannel = process_packet_batch(
                            batch, writer, poi, port, inputsource, deskew, subchanneling, subchanneling_bits, first_timestamp, last_packet_time, 
                            rounding_factor, subnet, secret_message, message_index, bitlength, last_poi_time, counter_poi, match_number, match_cycle, cr_received_pdus, cr_correctly_matched_pdus, 
                            multihashing, ooodelivery, 
                            send_chunks, last_data_per_subchannel, ecc, checksum_length, packetloss_percentage, packetdelay, delayAdjustmentTerm, packetjitter, 
                            saveWithPointer, pointer_template, verbose
                        )
                        
                        # Assert that last_data_per_subchannel is a dictionary
                        assert isinstance(last_data_per_subchannel, dict), "last_data_per_subchannel must be a dictionary."
    
                        total_bytes_processed += sum(len(pkt) for pkt in batch)
                        total_pdus_processed += len(batch)
                        batch = []
                        logger.info(f"SHPsimulator for {comment_field}: Batch {str(total_pdus_processed // MAX_BATCH_SIZE)} done, so far {str(match_number)} matches.")

                # Process any remaining packets in the last batch
                if batch:
                    message_index, last_packet_time, counter_poi, match_number, match_cycle, send_chunks, last_data_per_subchannel = process_packet_batch(
                        batch, writer, poi, port, inputsource, deskew, subchanneling, subchanneling_bits, first_timestamp, last_packet_time, 
                        rounding_factor, subnet, secret_message, message_index, bitlength, counter_poi, match_number, match_cycle, multihashing, ooodelivery, 
                        send_chunks, last_data_per_subchannel, ecc, checksum_length, packetloss_percentage, packetdelay, delayAdjustmentTerm, packetjitter, pointer_template, verbose
                    )
                    total_bytes_processed += sum(len(pkt) for pkt in batch)
                    total_pdus_processed += len(batch)

            # Calculate time elapsed during this pcap file and add it
            time_elapsed_in_file = last_timestamp - first_timestamp if first_timestamp < float('inf') else 0
            total_captured_time += time_elapsed_in_file
                                   
    return total_bytes_processed, total_pdus_processed, counter_poi, match_number, match_cycle, send_chunks, last_packet_time, last_data_per_subchannel, total_captured_time, cr_received_pdus, cr_correctly_matched_pdus

def find_pcap_files(folder):
    return sorted(glob.glob(os.path.join(folder, '*.pcap')) + glob.glob(os.path.join(folder, '*.pcapng')))
    
def main():
    # script version
    version_number = '10.0'
    version = 'V' + version_number
    
    # Get the directory where the script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Change the working directory to the script's directory
    os.chdir(script_dir)
    
    # parse command line arguments
    parser = argparse.ArgumentParser(description='Analyze pcap files for SHP covert channel communications.')
    # SHP parameterization
    parser.add_argument('--capfolder', default='pcap-test', help='Folder containing pcap files.')
    parser.add_argument('poi', choices=['all', 'subnet', 'broadcast_domain', 'port'], help='Defines PDUs of interest (POI).')
    parser.add_argument('subnet', help='Subnet address in CIDR notation, e.g. 10.0.0.0/24.')
    parser.add_argument('--port', type=int, default=80, help='TCP/UDP port number for the port poi mode.') 
    parser.add_argument('--inputsource', choices=['IPD', 'ISD', 'ISPN', 'ICD', 'timestamp', 'payload', 'tcp_seq'], default='IPD', help='Defines source of the pointer data. Default=IPD.') # IPD=inter packet delay; ISD=inter signal delay; ISPN=inter signal packet number
    parser.add_argument('--deskew', choices=['none', 'sha3', 'md5', 'log', 'power'], default='sha3', help='Defines deskew transformation.')
    parser.add_argument('--rounding_factor', type=int, default=4, help='Rounding factor.')
    parser.add_argument('--bitlength', type=int, default=8, help='Number of bits for hash and message comparison.') # basic chest length
    parser.add_argument('--subchanneling', choices=['none', 'baseipd', 'iphash', 'clock', 'clockhash'], default='none', help='Defines how subchannel split is calculated.')
    parser.add_argument('--subchanneling_bits', type=int, default=0, help='Number of bits used for multiplex subchannel number. Default=0')
    parser.add_argument('--outfolder', help='Output folder name. Defaults to current date.')
    parser.add_argument('--secret', default='secret_udhr.txt', help='File containing the secret message.')
    parser.add_argument('--ecc', choices=['none', 'hamming', 'hamming+', 'inline-hamming+'], default='none', help='Type of error correction code. Allows matching near miss sequences. Default none.')
    parser.add_argument('--multihashing', type=int, default=0, help='Number of bits used to mark how many hash iterations are needed to determine the message chunk. Default 0 = disabled. ')
    parser.add_argument('--ooodelivery', type=int, default=0, help='Number of bits used to mark the future message chunk, determining the number of future chunks to be checked. Default 0 = disabled. Maximum allowed value is 8.') # assumes CR supports packet reordering 
    parser.add_argument('--silence', type=int, default=0, help='Number of milliseconds PoIs must be apart (= phi or silent interval). Default 0 = disabled.') 
  
    # robustness manipulation parameters
    parser.add_argument('--simulateCR', action='store_true', default=False, help='When set will also simulate covert reiceiver.')
    parser.add_argument('--packetloss', type=int, default=0, help='Percent of PDUs that are lost between CS and CR. Default 0 = disabled. Maximum allowed value is 100.')
    parser.add_argument('--delay', type=int, default=0, help='Milliseconds of delay between CS observing PDU and CR receiving pointer. Default 0 = disabled.')
    parser.add_argument('--delayAdjustmentTerm', type=int, default=0, help='Adjustment Term used to align pointer and PDU timing. Default 0 = disabled.')
    parser.add_argument('--jitter', type=int, default=0, help='Milliseconds of delay variability between CS and CR. Default 0 = disabled.')
    
    # detectability parameters
    parser.add_argument('--saveWithPointer', action='store_true', default=False, help='Save source file with added ARP when a match is detected')
    
    # various parameters
    parser.add_argument('--comment', type=str, default=version, help='An optional comment field for the summary file')
    parser.add_argument('--verbose', action='store_true', help='Enable details csv file.')
    parser.add_argument('--batching', action='store_true', help='Enable batch processing.')
    args = parser.parse_args()
    
    # set output folder name
    if not args.outfolder:
        args.outfolder = './results/'
        
    # startup feedback
    if args.saveWithPointer:
        logger.info(f'Simulating SHP {args.comment} with captures in folder {os.path.basename(args.capfolder)} and saving pointers')
    else:
        logger.info(f'Simulating SHP {args.comment} with captures in folder {os.path.basename(args.capfolder)}')

    # Create the output directory if it does not exist
    os.makedirs(args.outfolder, exist_ok=True)
    
    # Check if the multihashing value exceeds the allowed values
    if (args.multihashing < 0) or (args.multihashing > 8):
        raise ValueError("--multihashing must be between 0 and 8.")
    
    # Check if the ooodelivery value exceeds the allowed values
    if (args.ooodelivery < 0) or (args.ooodelivery > 8):
        raise ValueError("--ooodelivery must be between 0 and 8.")
        
    # check ecc parameter and calc ecc length
    checksum_length = SHP_algos.get_checksum_length(args.ecc, args.bitlength)
    
    # Check if the packetloss value exceeds the allowed values
    if (args.packetloss < 0) or (args.packetloss > 100):
        raise ValueError("--packetloss must be between 0 and 100.")
        
    # Check if the delay value exceeds the allowed values
    if (args.delay < 0):
        raise ValueError("--delay must be 0 or more.")
        
    # init other variables
    rounding_factor = args.rounding_factor

    # add version number to the comment field
    comment_field = args.comment
    if (comment_field != version):
        comment_field = comment_field + ', ' + version
 
    pcap_files = find_pcap_files(args.capfolder)
    if not pcap_files:
        logger.error(f"No pcap files found in the specified folder: {args.capfolder}")
        exit(1)
        
    process_pcap_files(pcap_files, args.capfolder, args.subnet, args.poi, args.inputsource, args.deskew, args.subchanneling, args.subchanneling_bits, args.outfolder, args.secret, rounding_factor, args.bitlength, args.multihashing, args.ooodelivery, args.ecc, checksum_length, comment_field, args.batching, args.packetloss, args.delay, args.delayAdjustmentTerm, args.jitter, args.silence, args.simulateCR, args.saveWithPointer, args.verbose, port=args.port)
    
    logger.info(f'Completed simulation for {comment_field}')
    logger.info('Deskew cache usage was: ' + str(SHP_algos.apply_deskew.cache_info()))
    #logger.info('SHA3 cache usage was: ' + str(SHP_algos.sha3_hash_bits.cache_info()))
    logger.info('extract_message_bits cache usage was: ' + str(SHP_algos.extract_message_bits.cache_info()))  
    logger.info('compare_bits cache usage was: ' + str(SHP_algos.compare_bits.cache_info()))
    logger.info('compare_bits_ext cache usage was: ' + str(SHP_algos.compare_bits_ext.cache_info()))
        
if __name__ == "__main__":
    main()