#!/usr/bin/env python3

import os
import time
import scapy.all as scapy
from scapy.all import PcapReader, Ether, IP, IPv6, TCP, UDP, ARP
import hashlib
import ipaddress
import decimal
from functools import lru_cache # for the hash cache
import math
import utils.SHP_ecc as SHP_ecc # type: ignore

HWV4_BROADCAST = "ff:ff:ff:ff:ff:ff"
HWV6_BROADCAST = "33:33"
IPV4_BROADCAST = "255.255.255.255"
IPV6_BROADCAST = "ff0"
MAX_BATCH_SIZE = 100000

def string_to_bitstring(input_string):
    return ''.join(format(ord(char), '08b') for char in input_string)

def bitstring_to_string(bitstring):
    byte_chunks = [bitstring[i:i+8] for i in range(0, len(bitstring), 8)]
    return ''.join(chr(int(byte, 2)) for byte in byte_chunks)

def read_secret_message(filename):
    """Reads and returns the secret message from a given file."""
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            return file.read()
    except FileNotFoundError:
        raise Exception(f"Error: The file '{filename}' does not exist in {os.getcwd()}.")
    except UnicodeDecodeError:
        raise Exception(f"Error: The file '{filename}' is not in utf-8 encoding.")
    except Exception as e:
        raise Exception(f"An unexpected error occurred while reading '{filename}': {e}")
    
def write_secret_message(filename, bitstring, source_ip):
    reconstructed_string = ''
    try:
        # Convert bitstring to string
        reconstructed_string = bitstring_to_string(bitstring)
        
        # Get the current timestamp
        timestamp = time.time()
        timestamp_iso = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(timestamp))
        
        # Prepare the formatted message
        formatted_message = (
            f"{reconstructed_string}\n"
            f"received from {source_ip}\n"
            f"@{timestamp} ({timestamp_iso})\n"
        )
        
        # Write the formatted message to the file
        with open(filename, 'w', encoding='utf-8') as file:
            file.write(formatted_message)
        
        # Print the output details to the console
        # print(f"[INFO] Message written to {filename}")
        # print("[INFO] Written content:")
        # print(formatted_message)
    
    except (IOError, ValueError) as e:
        print(f"[ERR!] Writing secret message error: {e}")
    finally:
        return reconstructed_string

def is_ipv6_anycast(pkt):
    """TRUE IFF pkt is anycast """
    return IPv6 in pkt and (pkt[IPv6].dst.startswith("ff02::") or (Ether in pkt and pkt[Ether].dst.startswith("33:33:")))

def isPOI(pkt, poi, port, subnet, ignored):
    """TRUE IFF pkt is packet of interest in the mode given by poi."""
    try:
        # Ignore ARP requests for the specified IP address
        if pkt.haslayer(ARP):
            if pkt[ARP].op == 1 and pkt[ARP].pdst == ignored:  # ARP request
                return False

        # check by poi type
        if poi == 'all':
            return True
        if poi == 'port':
            return any((proto in pkt and (pkt[proto].sport == port or pkt[proto].dport == port)) for proto in [TCP, UDP])
        if poi == 'subnet' and IP in pkt:
            return in_subnet(pkt[IP].src, subnet) or in_subnet(pkt[IP].dst, subnet)
        if poi == 'broadcast_domain':
            return check_broadcast_domain(pkt, subnet)
    except Exception as e:
        print("[ERR!] Exception while checking PDU for POI", e, pkt)
        return False
    
    return False

# this filter can be used as an alternative to in-code poi filtering for LAN
STATIC_BPF_FILTER = "(ether dst ff:ff:ff:ff:ff:ff) or " \
             "(ip dst 10.255.255.255) or " \
             "(ip[16:2] & 0xFFFF = 0xFFFF) or " \
             "(ip6 multicast) or " \
             "(ether[0] & 1 != 0)"

        
def check_broadcast_domain(pkt, subnet):
    """Helper function to check if packet is in the broadcast domain."""
    
    conditions = []

    # Check if the packet contains an Ethernet layer
    if pkt.haslayer(Ether):
        # Add conditions related to Ethernet
        conditions.append(str(pkt[Ether].dst).lower() == HWV4_BROADCAST)
        conditions.append(str(pkt[Ether].dst).startswith(HWV6_BROADCAST))

    # Check if the packet contains an IPv6 layer
    if pkt.haslayer(IPv6):
        conditions.append(str(pkt[IPv6].dst).startswith(IPV6_BROADCAST))

    # Check if the packet contains an IPv4 layer
    if pkt.haslayer(IP):
        conditions.append(str(pkt[IP].dst) == IPV4_BROADCAST)
        conditions.append(str(pkt[IP].dst) == subnet_broadcast_address(subnet))
        
    return any(conditions)
    
def sha3_hash_bits(value, bitlength):
    """Calculates SHA3-256 hash of the given value and returns the first bitlength bits as well as the full hash digest."""
    hash_digest = hashlib.sha3_256(str(value).encode()).hexdigest()
    hash_bits = bin(int(hash_digest, 16))[2:].zfill(256)  # SHA3-256 produces 256 bits
    return hash_bits[:bitlength], hash_digest

@lru_cache(maxsize=65536) # cache frequent hash values
def md5_hash_bits(value, bitlength):
    """Calculates MD5 hash of the given value and returns the first bitlength bits."""
    hash_digest = hashlib.md5(str(value).encode()).hexdigest()
    hash_bits = bin(int(hash_digest, 16))[2:].zfill(128)  # MD5 produces 128 bits
    return hash_bits[:bitlength]
    
def extract_or_default(packet, layer, field, default):
    """
    Helper function to extract a field from a packet layer, or use default if not present.
    """
    if layer in packet:
        return getattr(packet[layer], field, default)
    return default

def parse_datapacket(pkt, inputsource, deskew, bitlength, rounding_factor, subchanneling, subchanneling_bits, multihashing, multihashing_count, ooodelivery, ecc, checksum_length, last_packet_time, last_data_per_subchannel, first_timestamp, message_chunk):
    """
    Helper function to extract data from a data channel packet.
    """

    # Calculate subchannel if mux is used; Default=0
    subchannel = get_subchannel(pkt, subchanneling, subchanneling_bits, last_packet_time, rounding_factor)

    # if we count packets per subchannel, increment now
    if (inputsource == 'ISPN'):
        ispn_counter = last_data_per_subchannel.get(subchannel)
        ispn_counter = (ispn_counter + 1) if ispn_counter is not None else 0
        last_data_per_subchannel[subchannel] = ispn_counter

    # Calculate source_data per current subchannel
    source_data = get_source_data(pkt, inputsource, subchannel, last_data_per_subchannel, first_timestamp)

    # round source data if applicable
    if inputsource in ('IPD', 'ISD', 'ICD', 'timestamp'):
        source_data = round(source_data, rounding_factor)
        
    # Apply deskewing transformation to get message + ecc
    deskewed_bits = apply_deskew(source_data, deskew, bitlength + checksum_length)

    #print(f'[DEBG] original source:{source_data} | deskewed: {deskewed_bits} | length {bitlength + checksum_length}')

    # if we use multihashing, do it
    if (multihashing != 0):
        _, hash_digest = sha3_hash_bits(deskewed_bits, bitlength + checksum_length)
        #print(f"[DEBG] multihashing 0 in {multihashing_count}| deskewed_bits={deskewed_bits} | ecc={ecc}:{checksum_length} | {hash_digest}")

        for i in range(1, multihashing_count + 1):
            deskewed_bits, hash_digest = sha3_hash_bits(hash_digest, bitlength)
            #print(f"[DEBG] multihashing {i} in {multihashing_count}| deskewed_bits={deskewed_bits} | ecc={ecc}:{checksum_length} | {hash_digest}")

    # update last data to this data
    if (inputsource == 'ISD'): # if we use inter signal timing, NOW is a signal
        last_data_per_subchannel[subchannel] = pkt.time

    # check the ecc
    if (ecc != 'none'):
        message_chunk = message_chunk + deskewed_bits
        #print(f'One... {message_chunk} > {checksum_length}')
        if (ecc != 'inline-hamming+') and (len(message_chunk) > checksum_length):
            #print('Two...')
            deskewed_bits, checksum_should_bits = SHP_ecc.extract_hamming_checksum(message_chunk)

            #print(f'[DEBG] ecc={ecc} | deskewed={deskewed_bits} | checksum should:{checksum_should_bits} | chunk: {message_chunk} | checksum length {checksum_length}')
            eccmatch, deskewed_bits, checksum_is_bits = SHP_ecc.check_checksum(ecc, deskewed_bits, checksum_should_bits, message_chunk, checksum_length)
            
            if eccmatch:
                deskewed_bits = message_chunk

            #print(f'[DEBG] ecc={ecc} {eccmatch} | checksum: should:{checksum_should_bits} ? {checksum_is_bits}:is | deskew after parting: {deskewed_bits}')

            message_chunk = ''
        else:
            eccmatch = True
        
    else:
        eccmatch = True
 
    return source_data, deskewed_bits, subchannel, last_packet_time, last_data_per_subchannel, first_timestamp, eccmatch


def isMatch(pkt, inputsource, deskew, bitlength, rounding_factor, subchanneling, subchanneling_bits, multihashing, ooodelivery, ecc, checksum_length, secret_message_bitstring, index, first_timestamp, last_data_per_subchannel, last_packet_time, send_chunks):
    
    # Calculate subchannel if mux is used; Default=0
    subchannel = get_subchannel(pkt, subchanneling, subchanneling_bits, last_packet_time, rounding_factor)

    # if we count packets per subchannel, increment now
    if (inputsource == 'ISPN'):
        ispn_counter = last_data_per_subchannel.get(subchannel)
        ispn_counter = (ispn_counter + 1) if ispn_counter is not None else 0
        last_data_per_subchannel[subchannel] = ispn_counter

    # Calculate source_data per current subchannel
    source_data = get_source_data(pkt, inputsource, subchannel, last_data_per_subchannel, first_timestamp)

    #print(f'[DEBG] isMatch source data: {source_data} | last {last_data_per_subchannel} | first {first_timestamp}')

    # round source data if applicable
    if inputsource in ('IPD', 'ISD', 'ICD', 'timestamp'):
        source_data = round(source_data, rounding_factor)

    # Apply deskewing transformation
    deskewed_bits = apply_deskew(source_data, deskew, bitlength + checksum_length)

    #print(f'[DEBG] original source:{source_data} | deskewed: {deskewed_bits} | length {bitlength + checksum_length}')

    # ooodelivery: go through message chunks to be send and check if we have a match
    msg_chunk_range = 2 ** ooodelivery if (ooodelivery > 0) else 1
    for message_chunk in range(msg_chunk_range):
        checking_index = index + message_chunk % (len(secret_message_bitstring) * 8 // bitlength) # index to check is relative to the message
                
        # Skip this message chunk if it has already been succesfully send
        if (ooodelivery > 0) and (checking_index in send_chunks):
            continue
                    
        # these are the message bits we currently want to find a match for
        message_bits = extract_message_bits(secret_message_bitstring, checking_index, bitlength, ecc)
        
        # multihashing: use the full hash digest as our source, so we get max entropy
        if (multihashing != 0):
            _, hash_digest = sha3_hash_bits(deskewed_bits, bitlength + checksum_length)

        for i in range(0, 2 ** multihashing):
            # --- check if we have a match ---
                    
            if (ecc == 'none') or (ecc == 'inline-hamming+'): # check for exact raw match
                match, message_bits, deskewed_bits = compare_bits(message_bits, deskewed_bits)
            elif (ecc == 'hamming'): # check for exact match including checksum
                message_with_ecc_bits = SHP_ecc.checksum(message_bits, ecc)
                match, message_with_ecc_bits, deskewed_bits = compare_bits(message_with_ecc_bits, deskewed_bits)                        
            elif (ecc == 'hamming+'): # check for match with tolerant checksum
                message_with_ecc_bits = SHP_ecc.checksum(message_bits, ecc)
                match, message_with_ecc_bits, deskewed_bits = compare_bits_ext(message_with_ecc_bits, deskewed_bits, 1)

            #print(f"[DEBG] multihashing {i} in {2 ** multihashing}| match={match} | message bits {message_bits} ? {deskewed_bits} deskewed bits | ecc={ecc}:{checksum_length} | {hash_digest}")

            if match:
                return match, source_data, message_bits, deskewed_bits, subchannel, checking_index, i
            
            # using multihashing means we always use SHA3 on the full hash digest maximize recursive entropy
            if (multihashing != 0):
                deskewed_bits, hash_digest = sha3_hash_bits(hash_digest, bitlength + checksum_length)

    return match, source_data, message_bits, deskewed_bits, subchannel, checking_index, 0
    
def get_source_data(pkt, inputsource, subchannel, last_data_per_subchannel, first_timestamp):
    """Calculates the network source data used as a base for deskewing and comparison.""" 
    last_data = last_data_per_subchannel.get(subchannel)

    #print(f"[DEBG] get_source_data: timestamp {pkt.time} | source: {inputsource} | channel {subchannel} | last {last_data_per_subchannel} | first {first_timestamp}")
    
    if (inputsource == 'IPD'): # inter packet delay; last data is previous PDU time
        return (pkt.time - last_data) if last_data is not None else 0
    elif (inputsource == 'ISD'): # inter signal delay; last data is time of last signal
        return (pkt.time - last_data) if last_data is not None else (pkt.time - first_timestamp)
    elif (inputsource == 'ISPN'): # inter signal packet number; last data is number of packets last signal was ago
        return last_data if last_data is not None else 0
    elif (inputsource == 'timestamp'): # PDU timestamp
        return (pkt.time)
    elif (inputsource == 'ICD'): # inter connection delay
        return (pkt.time - first_timestamp)
    elif (inputsource == 'payload'): # PDU payload or ethernet source if no raw data found
        eth_src = extract_or_default(pkt, scapy.Ether, 'src', '00:00:00:00:00:00')
        payload = bytes(pkt[scapy.Raw].load) if scapy.Raw in pkt else bytes(eth_src, 'utf-8')
        return payload
    elif (inputsource == 'tcp_seq'): # TCP sequence number or ethernet source if no TCP
        eth_src = extract_or_default(pkt, scapy.Ether, 'src', '00:00:00:00:00:00')
        tcp_seq = extract_or_default(pkt, scapy.TCP, 'seq', eth_src)
        return tcp_seq
    else:
        raise ValueError(f"Unknown inputsource: {inputsource}")
        
def get_subchannel(pkt, subchanneling, subchanneling_bits, last_packet_time, rounding_factor):
    """Calculate the multiplexing subchannel. Default is 0."""
    subchannel = 0
    
    if (subchanneling == 'none'):
        # no subchannels. cipd is just the rounded base ipd.
        return subchannel
    elif subchanneling == 'baseipd':
        # subchannels by first bits of rounded and hashed baseipd
        # get base ipd. if there was no previous POI, it's zero
        base_ipd = pkt.time - last_packet_time if last_packet_time is not None else 0
        ipd_rounded = round(base_ipd, rounding_factor)
        baseipdhash, _ = sha3_hash_bits(ipd_rounded,subchanneling_bits)
        return int(baseipdhash,2)
    elif subchanneling == 'iphash':
        # subchannels by first bits of the hashed source ip. if non-ip then use 0 as subchannel
        try:
            if IP in pkt:
                result, _ = sha3_hash_bits(pkt[IP].src, subchanneling_bits)
                return int(result, 2)
        except Exception as e:
            # Handles cases where the packet might be malformed or lacks expected data
            print("[ERR!] PDU used for iphash subchannel determination is malformed or missing expected data.")
            return 0
    elif subchanneling == 'clock':
        # subchannel by last bits of the recorded PDU arrivel time. assumes synchronized clocks of CS and CR.
        try:
            # Attempt to extract and convert the timestamp to an integer
            timestamp = int(pkt.time)
        except AttributeError as e:
            # If 'pkt.time' does not exist, subchannel stays 0
            print("[ERR!] PDU used for clock time is malformed or missing timestamp.")
            return 0
        except ValueError:
            # If 'pkt.time' is not in a valid format to be converted to integer directly
            # Interpret its binary value as a base-2 integer
            binary_string = format(pkt.time, 'b')
            timestamp = int(binary_string, 2)
                
        # Extract the rightmost subchanneling_bits bits by bitwise AND: Mask with 'subchanneling_bits' number of 1s, and apply the mask to 'ipd
        return timestamp & ((1 << subchanneling_bits) - 1)
    elif subchanneling == 'clockhash':
        # subchannel by hashed date and timestamp
        try:
            timestamp = int(pkt.time)
            result, _ = sha3_hash_bits(timestamp, subchanneling_bits)
            return int(result, 2)
        except Exception as e:
            # If 'pkt.time' does not work, subchannel stays 0
            print("[ERR!] PDU used for clock time is malformed or missing timestamp.")
            return 0
    
    return subchannel

@lru_cache(maxsize=65536) # cache frequent deskew values
def apply_deskew(raw_data, deskew, bitlength):
    """Applies the specified deskewing method to the raw_data."""    
    if deskew == 'sha3':
        result, _ = sha3_hash_bits(raw_data, bitlength)
        return result
    elif deskew == 'md5':
        return md5_hash_bits(raw_data, bitlength)
    elif deskew == 'log':
        if isinstance(raw_data, decimal.Decimal):
            raw_data = float(raw_data)  # Convert Decimal to float for compatibility
        
        # Protect against non-positive values for log1p
        if raw_data <= 0:
            raw_data = 0.0001  # A small positive number to avoid -inf or NaN
 
        log_result = math.log1p(raw_data) * 1e6
        if math.isnan(log_result):
            log_result = 0  # Handle potential NaN by setting to a default value
            
        # Convert float to an integer representation (rounded to the nearest integer)
        log_result = int(log_result*10000)
            
        # Convert number to binary, stripping the '0b' prefix
        binary_str = bin(log_result)[2:]
    
        # Ensure the binary string has at least 'bitlength' characters, pad with zeros if not
        if len(binary_str) < bitlength:
            binary_str = binary_str.zfill(bitlength)
    
        # Get the last 'bitlength' bits
        return binary_str[-bitlength:]
    elif deskew == 'power':
        if isinstance(raw_data, decimal.Decimal):
            raw_data = float(raw_data)  # Convert Decimal to float for compatibility
            
        ipd_transformed = math.power(raw_data + 1, 0.5)  # Square root transformation
        return format(int(ipd_transformed * 1e6), f'0{bitlength}b')
    elif deskew == 'none':
        return format(int(raw_data), f'0{bitlength}b') # BUG? This looks wrong
    
@lru_cache(maxsize=65536) # cache frequent message bits
def extract_message_bits(secret_message_bitstring, index, bitlength, ecc):
    """Extracts chunk from message bitstring, cycling if necessary."""
    
    if (ecc == 'inline-hamming+'):
        # Initialize the bitstring with ECC
        ecc_bitstring = ''
        
        # Add ECC bits after every `bitlength` message bits
        for i in range(0, len(secret_message_bitstring), bitlength):
            message_segment = secret_message_bitstring[i:i + bitlength]
            if len(message_segment) < bitlength:
                # Pad the last segment if it's shorter than bitlength
                message_segment = message_segment.ljust(bitlength, '0')
            ecc_bits = SHP_ecc.checksum(message_segment, 'hamming+')
            ecc_bitstring += message_segment + ecc_bits
            
        secret_message_bitstring = ecc_bitstring
    
    # find the cycle through the message bits based on index
    cycle_bits = secret_message_bitstring * ((index * bitlength // len(secret_message_bitstring)) + 1)
    start_bit = (index * bitlength) % len(secret_message_bitstring)
    return cycle_bits[start_bit:start_bit + bitlength]

@lru_cache(maxsize=65536) # cache frequent compare results
def compare_bits(message_bits, deskewed_bits):
    """
    Compare two bit sequences to determine if they match.

    This function takes two sequences of bits, `message_bits` and `deskewed_bits`,
    and checks if they are identical. It raises a ValueError if the lengths of the
    two sequences do not match. The function returns a tuple containing:
    - A boolean indicating whether the two sequences match.
    - The original `message_bits` sequence.
    - The original `deskewed_bits` sequence.
    """
    if len(message_bits) != len(deskewed_bits):
        raise ValueError(f"Length of message bits ({str(len(message_bits))}) and deskewed bits ({str(len(deskewed_bits))}) must be the same.")
        
    match = message_bits == deskewed_bits
    return match, message_bits, deskewed_bits

@lru_cache(maxsize=65536) # cache frequent compare results  
def compare_bits_ext(message_bits, deskewed_bits, t):
    """Compares extracted message bits with deskewed bits allowing up to t bit flips."""
    
    if len(message_bits) != len(deskewed_bits):
        raise ValueError(f"Length of message bits ({str(len(message_bits))}) and deskewed bits ({str(len(deskewed_bits))}) must be the same.")
    
    flips = bit_flip_count(message_bits, deskewed_bits)
    match = flips <= t
    return match, message_bits, deskewed_bits
    
def extract_deskewed_bits(message_bits, bitlength):
    message_bits_extracted = message_bits[:bitlength]
    return message_bits_extracted
    
def decode_message_bitstring(message_bits):
    # Step 1: Initialize a byte array
    byte_array = bytearray()
    
    # Step 2: Convert every 8 bits into a byte
    for i in range(0, len(message_bits), 8):
        byte_segment = message_bits[i:i+8]
        if len(byte_segment) == 8:
            byte = int(byte_segment, 2)
            byte_array.append(byte)
    
    # Step 3: Decode the byte array using ISO-8859-1 encoding
    message = byte_array.decode('iso-8859-1')
    return message
   
def bit_flip_count(bits1, bits2):
    """Counts the number of different bits (bit flips) between two bit strings."""
    return sum(b1 != b2 for b1, b2 in zip(bits1, bits2))

@lru_cache(maxsize=256) # cache frequent ips in subnet    
def in_subnet(ip, network):
    """Check if an IP is in a given subnet."""
    return ipaddress.ip_address(ip) in ipaddress.ip_network(network)

@lru_cache(maxsize=8) # cache frequent broadcast address
def subnet_broadcast_address(subnet):
    """Returns the broadcast adress of the given network"""
    return str(ipaddress.ip_network(subnet, strict=False).broadcast_address)
    
def shp_transmitter(pdu, args, writer, icd_start, inputsource, deskew, bitlength, multihashing, ooodelivery, ecc, secret_message, index, last_packet_time, last_data_per_subchannel, last_pdu_time, rounding_factor, first_timestamp, verbose):
    """
    calculates the SHP algorithm results for the given PDU
    
    Args:
        pdu: the scapy PDU
        args: command line arguments containing settings (poi, inputsource, bitlength, rounding_factor, deskew, subchanneling, subchanneling_bits, ooodelivery, multihashing)
        icd_start: timestamp of connection start
    Returns:
        poi: TRUE iff the pdu was a poi
        match: TRUE iff the pdu matches the next secret message chunk
        index: the new chunk position in the message after macthing
        last_received_per_subchannel: the new list of input source dependend comparators
    """
   
    try:
        match = False
        
        # Default values for per-PDU indicies
        multihashing_index = 0
        checking_index = 0
        
        # check if poi
        packet_interest = isPOI(pdu, args.poi, args.port, args.subnet)
        
        if packet_interest:
            
            # Calculate subchannel if mux is used; Default=0
            subchannel = get_subchannel(pdu, args.subchanneling, args.subchanneling_bits, last_pdu_time, rounding_factor)
            
            # if we count packets per subchannel, increment now
            if (inputsource == 'ISPN'):
                ispn_counter = last_data_per_subchannel.get(subchannel)
                ispn_counter = (ispn_counter + 1) if ispn_counter is not None else 0
                last_data_per_subchannel[subchannel] = ispn_counter
            
            # Calculate source_data per current subchannel
            source_data = get_source_data(pdu, inputsource, subchannel, last_data_per_subchannel, first_timestamp)
                
            # round source data if applicable
            if inputsource in ('IPD', 'ISD', 'ICD', 'timestamp'):
                source_data = round(source_data, rounding_factor)
        
            # Apply deskewing transformation (default == SHA3 hashing)
            deskewed_bits = apply_deskew(source_data, deskew, bitlength + checksum_length)
            
            # go through message chunks to be send and check if we have a match
            msg_chunk_range = 2 ** ooodelivery if (ooodelivery > 0) else 1
            for message_chunk in range(msg_chunk_range):
                checking_index = index + message_chunk % (len(secret_message) * 8 // bitlength) # index to check is relative to the message
                
                # Skip this message chunk if it has already been succesfully send
                if (ooodelivery > 0) and (checking_index in send_chunks):
                    continue
                    
                # get current message bits
                message_bits = extract_message_bits(secret_message, checking_index, bitlength, ecc)
                
                # using multihashing means we always use SHA3 after the first check
                if (multihashing != 0):
                    current_hash, _ = sha3_hash_bits(source_data, bitlength + checksum_length)
                
                for i in range(0, 2 ** multihashing):
                    # --- check if we have a match ---
                    
                    if (ecc == 'none') or (ecc == 'inline-hamming+'): # check for exact raw match
                        match, message_bits, deskewed_bits = compare_bits(message_bits, deskewed_bits)
                    elif (ecc == 'hamming'): # check for exact match including checksum
                        message_with_ecc_bits = SHP_ecc.checksum(message_bits, ecc)
                        match, message_bits, deskewed_bits = compare_bits(message_with_ecc_bits, deskewed_bits)                        
                    elif (ecc == 'hamming+'): # check for match with tolerant checksum
                        message_with_ecc_bits = SHP_ecc.checksum(message_bits, ecc)
                        match, message_with_ecc_bits, deskewed_bits = compare_bits_ext(message_with_ecc_bits, deskewed_bits, 1)
                                
                    # if we have a match, we progress through the message
                    if match:
                        
                        # increase match counter
                        match_number += 1
                        
                        if (inputsource == 'ISD'): # if we use inter signal timing, NOW is a signal
                            last_data_per_subchannel[subchannel] = pdu.time
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
                                           
                        break  # Stop checking further message chunks if a match is found.
                    
                    # if no match then next multihashing
                    if (multihashing != 0):
                        deskewed_bits, current_hash = sha3_hash_bits(current_hash, bitlength + checksum_length)
 
            # write details csv
            # hint: if enabled, this costs 4x performance!
            if (verbose):
                writer.writerow({
                    'source': source_data, 'subchannel': subchannel, 'deskewed_bits': deskewed_bits, 'message_bits': message_bits, 
                    'match': match, 'match_cycle': match_cycle, 'checking_index': checking_index, 'multihashing': multihashing_index, 
                })
                
            # update last data according to source; this was a POI
            if (inputsource == 'IPD'):     
                last_data_per_subchannel[subchannel] = pdu.time  # last data is this PDUs time

            return index, pdu.time, match_number, match_cycle, send_chunks, last_data_per_subchannel # Return the current packet time to update the last packet of interest time
    
    except Exception as e:
        # Initialize fallback values for logging or provide alternative logic
        message_bits = locals().get('message_bits', 'N/A')
        deskewed_bits = locals().get('deskewed_bits', 'N/A')
        index = locals().get('index', 'N/A')
        checksum_length = locals().get('checksum_length', 'N/A')
        
        # if we get an unhandled exception for a PDU we stop this script
        print(f'Exception while checking PDU with values msg_bits {message_bits}, deskewed_bits {deskewed_bits}, index {index}, checksum_length {checksum_length}', e, pdu)
        exit(2607)
        
    return index, last_packet_time, match_number, match_cycle, send_chunks, last_data_per_subchannel # Return the last packet of interest time unchanged if the current packet does not meet criteria

def shp_receptor(pdus, args, checksum_length, secret_message_bitstring, last_data_per_subchannel, last_pdu_time, first_timestamp):
    """
    given a list of received pdus finds the one pointed to and decodes its message chunk.
        1. sort the list of pdus by timestamp (unless args.inputsource == ISPN)
        2. select the least recently received poi as pdu pointed to
        3. decode data bits from pdu by applying inputsource and deskewing
        4. ecc 
        5. return results
    Args:
        pdus: the rotating list of pdus recently received in scapy format
        args: command line arguments containing shp settings (poi, inputsource, bitlength, rounding_factor, deskew, subchanneling, subchanneling_bits, ooodelivery, multihashing)
        secret_message: partial secret message so far received in string format
        last_data_per_subchannel: inputsource-dependant decoding information
            for ICD: last timetstamp per subchannel
            for ICD: connection start timestamp
            for ISD: least recent secret signal
            for ISPN: number of PDUs so far received
        last_pdu_time: timestamp of last baseipd (for ipd subchanneling by baseipd)
        first_timestamp: connection start (for ICD; also ISD checking before first internal signal)
    Returns:
        found: TRUE iff a poi match was found in the list
        secret_message: secret message so far received, amended with the new chunk if applicable
        last_data_per_subchannel: the new list of input source dependend comparators
        ecc_fail: TURE iff the received chunk is complete but failed ecc
    """
   
    ecc_fail = False
    found = False
    
    try:
        # Step 1: Sort the list of PDUs by timestamp (unless args.inputsource == ISPN)
        if args.inputsource != 'ISPN':
            pdus.sort(key=lambda pdu: pdu.time)

        # Step 2: Iterate through all PDUs starting with the least recent and check if it is a PDU of interest using isPOI
        selected_pdu = None
        for pdu in pdus:
            if isPOI(pdu, args.poi, args.port, args.subnet):
                selected_pdu = pdu
                found = True
                break

        if selected_pdu is None:
            return False, secret_message_bitstring, last_data_per_subchannel, ecc_fail
            
        # Calculate subchannel if needed; Default=0
        subchannel = get_subchannel(pdu, args.subchanneling, args.subchanneling_bits, last_pdu_time, args.rounding_factor)
        
        # decode raw input bits from pdu
        source_data = get_source_data(pdu, args.inputsource, subchannel, last_data_per_subchannel, first_timestamp)

        # round source data if applicable
        if args.inputsource in ('IPD', 'ISD', 'ICD', 'timestamp'):
            source_data = round(source_data, args.rounding_factor)
        
        # Apply deskewing transformation ("hashing")
        deskewed_bits = apply_deskew(source_data, args.deskew, args.bitlength + checksum_length)
        
        # apply multihashing if needed
        while args.multihashing > 0:
            deskewed_bits = sha3_hash_bits(deskewed_bits, args.bitlength, checksum_length)
            args.multihashing -= 1

        # take out the interesting bits from the resulting bitstring
        extracted_bits = extract_deskewed_bits(deskewed_bits, args.bitlength)
        
        # check ecc if applicable
        if (args.ecc != 'none'):
            ecc_fail = True
            if args.ecc in ('hamming', 'hamming+'):
                message_bits, checksum = SHP_ecc.extract_hamming_checksum(extracted_bits)
                
                ecc_fail = not SHP_ecc.check_hamming_checksum(message_bits, checksum)
                
                if ecc_fail:
                    return True, secret_message_bitstring, last_data_per_subchannel, True
                    
        # append new message bits to message
        secret_message_bitstring = secret_message_bitstring + message_bits
        
        return found, secret_message_bitstring, last_data_per_subchannel, ecc_fail

    except Exception as e:
        # Initialize fallback values for logging or provide alternative logic
        message_bits = locals().get('message_bits', 'N/A')
        deskewed_bits = locals().get('deskewed_bits', 'N/A')
        
        # if we get an unhandled exception for a PDU we display and log a warning
        print(f'Exception while checking PDU with values msg_bits {message_bits}, deskewed_bits {deskewed_bits}', e, pdu)

def create_pointer(src_ip, src_mac, target_ip):
    """
    Create an ARP request using Scapy.
    """
    # create ARP request
    arp_request = ARP(op=1, pdst=target_ip, psrc=src_ip, hwsrc=src_mac)
    
    # Wrap it in an Ethernet frame
    # EtherType 0x0806 is for ARP
    eth_frame = Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac, type=0x0806) / arp_request
    return eth_frame

def flush_poi_list(pkt, list_poi, silence):
    """
    Updates list_poi according to two conditions:
    1) Remove packets that are within 'silence' ms of the new packet 'pkt'.
    2) Remove packets that are older than 8000 ms relative to 'pkt'.

    This version returns the number of elements removed for each condition.

    :param pkt:      The new Scapy packet (with a .time attribute).
    :param list_poi: A list of existing Scapy packets to be updated.
    :param silence:  The threshold in milliseconds to check "younger" packets.
    :return:         A tuple (silence_removed, older_removed) with
                     counts for packets removed by each rule.
    """
    new_time = pkt.time
    silence_removed = 0
    older_removed = 0
    kept_packets = []

    for p in list_poi:
        diff_ms = (new_time - p.time) * 1000
        if diff_ms < silence:
            # Removed because it's within 'silence' ms
            silence_removed += 1
            #print(f'[DEBG] silence removed with ({new_time} - {p.time}) * 1000 = {diff_ms} < {silence}')
        elif diff_ms > 8000:
            # Removed because it's older than 8000 ms
            older_removed += 1
        else:
            # This packet is kept
            kept_packets.append(p)

    # Update list_poi only if any packets have been removed
    if silence_removed + older_removed > 0:
        list_poi[:] = kept_packets

    return silence_removed, older_removed
