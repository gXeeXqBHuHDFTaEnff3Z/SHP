import sys
import os
import time
import math
import collections
import itertools
import hashlib
import numpy as np
from threading import Timer
from operator import xor
from scapy.all import *
from bitstring import BitArray
import netifaces
from netaddr import *
import SHP_live_networking as SHP_live_networking
import bchlib
import csv
import uuid
import logging

# Set up comprehensive logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dystel_debug.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# -------------------------------
# Dummy defaults if no command-line parameters provided
# -------------------------------
MIN_ARGS_FOR_CS = 8    # [script, covert_message_file, number_of_chars, interface, logfile, mode, encoding_method, signal_arp]
MIN_ARGS_FOR_CR = 10   # For CR mode, additional two arguments are needed

# Get the directory of the script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Change the working directory
os.chdir(script_dir)

print("Current working directory:", os.getcwd())

# If not enough arguments are provided, we assume dummy defaults.
if len(sys.argv) < MIN_ARGS_FOR_CS:
    print("No command-line arguments provided. Using default dummy arguments.")
    # For sender (cs) mode, we need 8 arguments (sys.argv[0] is the script name)
    sys.argv = [sys.argv[0],
                "secret_message_long.txt",   # Covert Message File
                "1",                   # # of bytes at once (number_of_chars)
                "Realtek USB GbE Family Controller",                  # Interface (change as needed, e.g., "eth0")
                #"Qualcomm FastConnect 6900 Wi-Fi 6E Dual Band Simultaneous (DBS) WiFiCx Network Adapter #4",
                "dystel_cr.log",       # Logfile for percent coverage
                "cr",                  # Mode: 'cs' for sender (use 'cr' for receiver mode, but then add 2 more arguments)
                "trivial",             # Coding method: trivial (other options: trivial_robust, ext, ext_robust, ECC(experimental))
                "127.55.5.5",          # ARP Broadcast Target IP (dummy value)
                "127.0.0.1",
                "dystel_received.txt"
               ]
    # Note: If you wish to test the CR (receiver) mode, then set the mode to "cr" and add two more parameters:
    # "dummy_source_ip" and "dummy_received.txt" (e.g.,
    # sys.argv = [sys.argv[0], "dummy_message.txt", "2", "lo", "dummy_log.txt", "cr", "trivial", "192.168.1.255", "192.168.1.100", "dummy_received.txt"]
    
# Create a dummy covert message file if it does not exist.
dummy_message_file = sys.argv[1]
if not os.path.isfile(dummy_message_file):
    with open(dummy_message_file, "w") as f:
        f.write("This is a dummy covert message for testing.")

# -------------------------------
# Global variables for CSV statistics logging
# -------------------------------
# --- New Statistics Counters ---
pkt_interest_count = 0
poi_critical_fraction_count = 0
dyst_match_count = 0

# Create a unique ID for this run and record the start time.
run_uuid = uuid.uuid4()
start_time = time.time()
csv_stats_file = "statistics_cr.csv"

def update_csv_stats():
    """
    Calculate the current run statistics and update the CSV file.
    The CSV columns are:
      uuid, start, duration, packets, matches, avg_distance, bandwidth_per_sec, stego_bandwidth
    If an entry with the same uuid exists, it will be overwritten.
    """
    global run_uuid, start_time, pkt_interest_count, poi_critical_fraction_count, dyst_match_count, csv_stats_file, number_of_chars

    current_time = time.time()
    duration = current_time - start_time
    # Calculate average distance between matches
    avg_distance = (pkt_interest_count / dyst_match_count) if dyst_match_count > 0 else 0
    # Bandwidth per second: (number_of_chars*8*matches) / duration
    bandwidth_per_sec = (number_of_chars * 8 * dyst_match_count / duration) if duration > 0 else 0
    # Steganographic bandwidth: (number_of_chars*8) / (packets/match) = (number_of_chars*8 * matches) / packets
    stego_bandwidth = (number_of_chars * 8 * dyst_match_count / pkt_interest_count) if pkt_interest_count > 0 and dyst_match_count > 0 else 0

    row_data = {
        "uuid": str(run_uuid),
        "settings": f"{number_of_chars} chars, {encoding_method}, mode: {mode}",
        "start": start_time,
        "duration": duration,
        "packets": pkt_interest_count,
        "poi_critical_fraction": poi_critical_fraction_count,
        "matches": dyst_match_count,
        "avg_distance": avg_distance,
        "bandwidth_per_sec": bandwidth_per_sec,
        "stego_bandwidth": stego_bandwidth
    }

    # Read existing CSV rows (if any)
    rows = []
    if os.path.isfile(csv_stats_file):
        with open(csv_stats_file, mode='r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for r in reader:
                rows.append(r)

    # Update if a row with the same uuid exists; otherwise, append a new row.
    updated = False
    for r in rows:
        if r["uuid"] == str(run_uuid):
            r.update({k: row_data[k] for k in row_data})
            updated = True
            break
    if not updated:
        rows.append(row_data)

    # Write out the CSV file with header.
    with open(csv_stats_file, mode='w', newline='') as csvfile:
        fieldnames = ["uuid", "settings", "start", "duration", "packets", "poi_critical_fraction", "matches", "avg_distance", "bandwidth_per_sec", "stego_bandwidth", "comment"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

# -------------------------------
# (Rest of your original code follows below)
# -------------------------------

## Define global variables

global cm_array                # covert message split in array of sys.argv[2] characters
global cm_array_current        # current position of message to encode
global ba_curr                 # current bitarray to search for
global interface               # interface to receive and send messages
global logfile_percentCoverage_covertMessage  # file to log the percent fitting bits
global hwv4_broadcast          # MAC address for broadcasts (IPv4)
global ipv4_broadcast          # IP address for network broadcasts (IPv4)
global hwv6_broadcast          # MAC address for broadcasts (IPv6)
global ipv6_broadcast          # IPv6 address for network broadcasts
global signal_ipv6             # IPv6 Address that will trigger the signal
global signal_ether            # IPv6 Address that will trigger the signal
global DB
global DBtime
global encoding_method         # Method coding is achieved with
global timeslice_total         # timeslice to encode position within the hash
global timeslice_delay         # delay to calculate with for additional runtime
global latest_timestamp_cr_only
global number_of_chars
global bch
global masks
global robust
global oldPkt
global robustignore
global robustdelay
global timer
global ba_save
global sniffed_hash
global timestamp
global crit_fraction_high
global crit_fraction_low

### Configuration for ECC mode (experimental)
#BCH_POLYNOMIAL = 8219
#BCH_BITS = 1
#bch = bchlib.BCH(BCH_POLYNOMIAL, BCH_BITS)

# Detect and set the active interface cross-platform
interface = SHP_live_networking.find_and_select_active_interface()

# list interfaces recorded
SHP_live_networking.display_interfaces_and_selected(selected_iface=interface)

### Define collections for storage of packets
DB = collections.deque(maxlen=20000)
DBtime = collections.deque(maxlen=20000)

#### RepeatingTimer (used for robust mode)
class RepeatingTimer(object):
    def __init__(self, interval, f, *args, **kwargs):
        self.interval = interval
        self.f = f
        self.args = args
        self.kwargs = kwargs
        self.timer = None

    def callback(self):
        self.f(*self.args, **self.kwargs)

    def reset(self):
        print("RESET Timer")
        if self.timer:
            self.timer.cancel()
            self.timer = Timer(self.interval, self.callback)
            self.timer.start()
        else:
            self.timer = Timer(self.interval, self.callback)
            self.timer.start()

    def cancel(self):
        if self.timer:
            self.timer.cancel()

    def start(self):
        self.timer = Timer(self.interval, self.callback)
        self.timer.start()


##########
#### Signalling functions
##########

def isSignal(packet, prot):
    global signal_ipv6
    global signal_arp
    if prot == 'ipv6' and IPv6 in packet:
        if str(packet[IPv6].dst) == signal_ipv6:
            return True
        else:
            return False
    elif prot == 'arp' and ARP in packet:
        #print(f"ARP packet detected: {packet[ARP].pdst} -> {packet[ARP].psrc} (looking for {signal_arp} -> {signal_arp_from})")
        if str(packet[ARP].pdst) == signal_arp and str(packet[ARP].psrc) == signal_arp_from:
            return True
        else:
            return False
    else:
        return False

def isPktOfInterest(packet):
    global hwv4_broadcast
    global ipv4_broadcast
    global hwv6_broadcast
    global ipv6_broadcast
    # Dummy implementation - every IPv6 packet is "interesting"
    if isSignal(packet, 'arp'):
        return False

    try:
        if IPv6 in packet:
            if str(packet[Ether].dst).startswith(hwv6_broadcast):
                return True
            elif str(packet[IPv6].dst).startswith(ipv6_broadcast):
                return True
            else:
                return False
        if IP in packet:
            if str(packet[Ether].dst) == hwv4_broadcast:
                return True
            elif str(packet[IP].dst) == "255.255.255.255":
                return True
            elif str(packet[IP].dst) == ipv4_broadcast:
                return True
        if ARP in packet:
            if str(packet[Ether].dst) == hwv4_broadcast and str(packet[ARP].src) != "192.168.2.1":
                return True
        else:
            return False
    except:
        return False

def sendSignal(prot, addr, DB_pointer, hash_pointer):
    if prot == 'ipv6':
        sendIPv6(addr)
    elif prot == 'arp':
        sendARP(addr)
    else:
        pass

def sendARP(addr):
    global interface
    global ba_curr
    global cm_array_current
    global cm_array
    global logfile_percentCoverage_covertMessage
    global ba_save
    global sniffed_hash
    global timestamp
    global encoding_method
    sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=addr), iface=interface)
    if robust:
        if encoding_method.startswith("trivial"):
            cm_array_current += 1
            ba_curr = getStringToBinary(cm_array[cm_array_current])
        elif encoding_method.startswith("ext"):
            cm_array_current += 1
            ba_temp = getStringToBinary(cm_array[cm_array_current])
            ba_curr = ba_temp + getCheckSum(ba_temp)
        elif encoding_method.startswith("ECC"):
            cm_array_current += 1
            ba_curr = getStringToBinary_BCH(cm_array[cm_array_current])

        with open(logfile_percentCoverage_covertMessage, 'a') as log:
            log.write(str(timestamp) + ";" + str(sniffed_hash) + ";" + str(ba_save) + ";" +
                      str(getMatchPercent(list(ba_save), list(sniffed_hash))) + ";" + str(True) + '\n')
    return

def sendIPv6(addr):
    global interface
    command = "ndisc6 " + addr + " " + interface
    os.system(command)
    return

###################
##### Converting functions
###################
def getBinaryToString(bits):
    return bits.decode('utf-8')

def getBitStringToString(bits):
    """
    Convert bit string to string with enhanced error handling and logging
    """
    logger.debug(f"getBitStringToString called with bits: {repr(bits)}")
    logger.debug(f"Bits type: {type(bits)}, length: {len(bits) if bits else 'None'}")
    
    if not bits:
        logger.warning("Empty or None bits string received")
        return ""
    
    if len(bits) % 8 != 0:
        logger.warning(f"Bits length {len(bits)} is not divisible by 8, truncating to nearest byte boundary")
        # Truncate to nearest byte boundary
        bits = bits[:len(bits) - (len(bits) % 8)]
    
    try:
        result = ""
        for i in range(len(bits)//8):
            byte_bits = bits[i*8:i*8+8]
            logger.debug(f"Processing byte {i}: {byte_bits}")
            
            if len(byte_bits) == 8:
                byte_value = int(byte_bits, 2)
                logger.debug(f"Byte value: {byte_value} (0x{byte_value:02x})")
                
                # Check if byte is printable ASCII or extended ASCII
                if 0 <= byte_value <= 255:
                    try:
                        char = chr(byte_value)
                        # Only include printable characters or common whitespace
                        if char.isprintable() or char in '\r\n\t':
                            result += char
                            logger.debug(f"Added character: {repr(char)}")
                        else:
                            logger.debug(f"Skipping non-printable character: {byte_value}")
                            # For non-printable characters, we could:
                            # 1. Skip them (current approach)
                            # 2. Replace with '?' or similar placeholder
                            # 3. Use error handling strategy
                            result += '?'  # Replace with placeholder
                    except ValueError as e:
                        logger.warning(f"Could not convert byte value {byte_value} to character: {e}")
                        result += '?'
                else:
                    logger.warning(f"Byte value {byte_value} out of valid range")
                    result += '?'
        
        logger.debug(f"Final result: {repr(result)}")
        return result
        
    except Exception as e:
        logger.error(f"Error in getBitStringToString: {e}")
        logger.error(f"Input bits: {repr(bits)}")
        return ""  # Return empty string on error instead of crashing
 
def getStringToBinary(string):
    bin_value = BitArray(string.encode('utf-8')).bin
    return bin_value

def getStringToBinary_BCH(string):
    global bch
    bin_value = BitArray(string.encode('utf-8'))
    ecc = bch.encode(bin_value.bytes)
    return bin_value.bin + BitArray(ecc).bin

def getBinaryToString_BCH(bits):
    global bch
    inputBytes = BitArray(bin=bits).bytes
    data, ecc = inputBytes[:-bch.ecc_bytes], inputBytes[-bch.ecc_bytes:]
    bitflips, newData, newECC = bch.decode(data, ecc)
    try:
        string_to_return = newData.decode('utf-8')
    except UnicodeDecodeError:
        string_to_return = ""
    return string_to_return

########
### Getting values from packets, dbs
########

def getHashValue(input):
    try:
        hash = hashlib.sha512(input)
    except TypeError:
        hash = hashlib.sha512(input.encode('utf-8'))
    return hash

def getInputValues(packet):
    string = ""
    if robust:
        timestamp = str(int(time.time()))
    else:
        timestamp = str(int(time.time()/10))
    if IPv6 in packet:
        string = str(packet[IPv6].src) + timestamp
    elif IP in packet:
        string = str(packet[IP].chksum) + timestamp
    elif ARP in packet:
        string = str(packet[ARP].pdst) + str(packet[ARP].psrc) + timestamp
    return string

def getBitstringFromDB(DB_position):
    try:
        db_item = DB[DB_position]
        logger.debug(f"getBitstringFromDB({DB_position}) - DB item type: {type(db_item)}")
        
        # Check if the DB item is an empty string (critical fraction case)
        if db_item == "":
            logger.debug(f"getBitstringFromDB({DB_position}) - Found empty string (critical fraction)")
            res = ''
        else:
            # Normal case - should be a hash object
            res = BitArray(bytes=db_item.digest()).bin
            logger.debug(f"getBitstringFromDB({DB_position}) returning: {res[:50]}..." if len(res) > 50 else f"getBitstringFromDB({DB_position}) returning: {res}")
    except Exception as e:
        logger.error(f"Error in getBitstringFromDB({DB_position}): {e}")
        logger.error(f"DB item at position {DB_position}: {repr(DB[DB_position]) if DB_position < len(DB) else 'INDEX OUT OF RANGE'}")
        res = ''
    return res

def getSniffedHash(DB_position, Binary_position):
    global ba_curr
    global DB
    logger.debug(f"getSniffedHash called with DB_position={DB_position}, Binary_position={Binary_position}")
    logger.debug(f"ba_curr length: {len(ba_curr) if ba_curr else 'None'}")
    
    if not ba_curr:
        logger.warning("ba_curr is empty or None")
        return ""
    
    begin = Binary_position * len(ba_curr)
    end = (Binary_position+1) * len(ba_curr)
    
    full_bitstring = getBitstringFromDB(DB_position)
    if not full_bitstring:
        logger.warning(f"Empty bitstring from DB position {DB_position}")
        return ""
    
    if end > len(full_bitstring):
        logger.warning(f"Requested range [{begin}:{end}] exceeds bitstring length {len(full_bitstring)}")
        return ""
    
    result = full_bitstring[begin:end]
    logger.debug(f"getSniffedHash returning: {result}")
    return result

def getSniffedTime(DB_position):
    global DBtime
    return DBtime[DB_position]

def getSniffedHashList(DB_position):
    global ba_curr
    global DB
    logger.debug(f"getSniffedHashList called with DB_position={DB_position}")
    
    try:
        full_bitstring = getBitstringFromDB(DB_position)
        if not full_bitstring or not ba_curr:
            logger.warning("Empty bitstring or ba_curr in getSniffedHashList")
            return []
            
        number_of_vals = len(full_bitstring) / len(ba_curr)
        logger.debug(f"number_of_vals calculated: {number_of_vals}")
    except (AttributeError, ZeroDivisionError) as e:
        logger.error(f"Error calculating number_of_vals: {e}")
        number_of_vals = 0

    hashlist = []
    counter = 0
    while counter < number_of_vals:
        hash_segment = getSniffedHash(DB_position, counter)
        if hash_segment:  # Only add non-empty segments
            hashlist.append(hash_segment)
        counter += 1

    logger.debug(f"getSniffedHashList returning {len(hashlist)} items")
    return hashlist

##########
#### Special ext-mode functions for checksums and reversions
##########

def testCheckSum(hash):
    if number_of_chars == 1:
        return (list(map(int, list('{0:04b}'.format(np.count_nonzero(np.array(hash[:-4]).astype(int)))))) == hash[-4:])
    elif number_of_chars == 2:
        return (list(map(int, list('{0:05b}'.format(np.count_nonzero(np.array(hash[:-5]).astype(int)))))) == hash[-5:])
    else:
        print("Checksum not Calculated")
        exit(100)

def getMask(n, k):
    result = []
    for i in range(k+1):
        res = kbits(n, i)
        res.reverse()
        result.append(res)
    ret = [item for sublist in result for item in sublist]
    ret = list(map(list, ret))
    ret = list(map(lambda x: [int(y) for y in x], ret))
    return ret

def getCheckSum(hash):
    if number_of_chars == 1:
        return ('{0:04b}'.format(np.count_nonzero(np.array(hash).astype(int))))
    elif number_of_chars == 2:
        return ('{0:05b}'.format(np.count_nonzero(np.array(hash).astype(int))))
    else:
        print("Checksum not Calculated")
        exit(100)

def checkBitFlips(hash, orig):
    global masks
    if number_of_chars == 1:
        cflen = -4
    elif number_of_chars == 2:
        cflen = -5
    else:
        print("Checksum Length too long")
        exit(100)
    for i in masks:
        cur_flipped = list(map(lambda x, y: x ^ int(y), hash, list(i)))
        if testCheckSum(cur_flipped):
            if cur_flipped[:cflen] == orig[:cflen]:
                return True
            else:
                return False
        else:
            pass
    return False

def revertBitFlip(hash):
    global masks
    if number_of_chars == 1:
        cflen = -4
    elif number_of_chars == 2:
        cflen = -5
    else:
        print("Checksum Length too long")
        exit(100)

    for i in masks:
        cur_flipped = list(map(lambda x, y: x ^ int(y), hash, list(i)))
        if testCheckSum(cur_flipped):
            return cur_flipped[:cflen]
        else:
            pass

def kbits(n, k):
    result = []
    for bits in itertools.combinations(range(n), k):
        s = ['0'] * n
        for bit in bits:
            s[bit] = '1'
        result.append(''.join(s))
    return result

def getMatchPercent(a, b):
    if len(a) != len(b):
        raise ValueError("Length of arrays does not match!")
    return np.count_nonzero(np.array(a) == np.array(b)) / len(a)

##########
##### Main functions for CS and CR
##########

def cs_sniffing(packet):
    global DB, signal_ipv6, cm_array, cm_array_current, ba_curr, logfile_percentCoverage_covertMessage
    global timestamp, sniffed_hash, robust, oldPkt, robustdelay, timer, ba_save
    global crit_fraction_high, crit_fraction_low
    sig_send = False

    if isPktOfInterest(packet):
        if robust:
            if oldPkt is None:
                oldPkt = packet
            elif (float(packet.time - oldPkt.time) < robustdelay):
                oldPkt = packet
                try:
                    timer.cancel()
                except:
                    pass
                return

        ba_save = ba_curr
        timestamp = time.time() + timeslice_delay
        critical_fraction, seconds = math.modf(timestamp)
        
        # Check if this is a critical fraction (where we don't want to process the hash)
        isCritFraction = (critical_fraction > crit_fraction_high or critical_fraction < crit_fraction_low)
        
        if isCritFraction:
            logger.debug(f"Critical fraction detected: {critical_fraction}")
            DB.appendleft("")  # Add empty string marker for critical fractions
        else:
            input1 = getInputValues(packet)
            hash_val = getHashValue(input1)
            DB.appendleft(hash_val)
            logger.debug(f"Added hash to DB at critical_fraction: {critical_fraction}")

        try:
            sniffed_hash = getSniffedHashList(0)[0]
        except IndexError:
            sniffed_hash = ""

        if encoding_method.startswith("trivial"):
            if ba_curr == sniffed_hash and not isCritFraction:
                if robust:
                    timer.start()
                else:
                    cm_array_current += 1
                    ba_curr = getStringToBinary(cm_array[cm_array_current])
                    print("Found correct hash")
                    sendSignal('arp', signal_arp, 0, 0)
                    sig_send = True
            else:
                print("NoMatch")

        elif encoding_method.startswith("ext"):
            if sniffed_hash != "" and getMatchPercent(list(sniffed_hash), list(ba_curr)) >= 0.8 and not isCritFraction:
                sniffed_hash_int = list(map(int, sniffed_hash))
                ba_curr_int = list(map(int, ba_curr))
                if checkBitFlips(sniffed_hash_int, ba_curr_int):
                    if robust:
                        timer.start()
                    else:
                        cm_array_current += 1
                        ba_temp = getStringToBinary(cm_array[cm_array_current])
                        ba_curr = ba_temp + getCheckSum(ba_temp)
                        print("Found correct hash")
                        sendSignal('arp', signal_arp, 0, 0)
                        sig_send = True
                else:
                    print("NoMatch")
            else:
                print("NoMatch")

        elif encoding_method.startswith("ECC"):
            if getBinaryToString_BCH(sniffed_hash) == getBinaryToString_BCH(ba_curr) and not isCritFraction:
                if robust:
                    timer.start()
                else:
                    cm_array_current += 1
                    ba_curr = getStringToBinary_BCH(cm_array[cm_array_current])
                    print("Found correct hash")
                    sendSignal('arp', signal_arp, 0, 0)
                    sig_send = True

        print("Sniffed Hash: \t", sniffed_hash)
        print("Target Hash: \t", ba_save)
        try:
            print("Match Percent: \t", getMatchPercent(list(ba_save), list(sniffed_hash)))
        except ValueError:
            print("Critical Second Fraction Detected")
        print("----")

        with open(logfile_percentCoverage_covertMessage, 'a') as log:
            try:
                log.write(str(timestamp) + ";" + str(sniffed_hash) + ";" + str(ba_save) + ";" +
                          str(getMatchPercent(list(ba_save), list(sniffed_hash))) + ";" + str(sig_send) + '\n')
            except ValueError:
                log.write(str(sniffed_hash) + ";" + str(ba_save) + ";;" + str(sig_send) + '\n')
    else:
        pass

def cr_sniffing(packet):
    global DB, latest_timestamp_cr_only, DBtime, robust, crit_fraction_high, crit_fraction_low
    if isSignal(packet, 'arp'):
        print("WOW! That's a signal!")
        logger.info("Signal detected - processing message")

        # update statistics
        global pkt_interest_count, poi_critical_fraction_count, dyst_match_count
        pkt_interest_count += 1
        dyst_match_count += 1
        update_csv_stats()

        packet.show()
        string_message = ""
        binary_message = ""
        
        logger.debug(f"Processing signal with encoding_method: {encoding_method}")
        
        if encoding_method.startswith("trivial"):
            if robust:
                rob_timestamp = time.time()
                for pckCount in range(0, 200):
                    hash_segment = getSniffedHash(pckCount, 0)
                    logger.debug(f"Robust mode - checking packet {pckCount}, hash: {hash_segment}")
                    
                    if hash_segment:  # Only process non-empty hashes
                        decoded_string = getBitStringToString(hash_segment)
                        print(decoded_string)
                        logger.debug(f"Decoded string from packet {pckCount}: {repr(decoded_string)}")
                    
                    if getSniffedTime(pckCount) <= (rob_timestamp - robustignore):
                        binary_message = hash_segment
                        logger.debug(f"Selected binary_message from packet {pckCount}: {binary_message}")
                        break
            else:
                binary_message = getSniffedHash(0, 0)
                logger.debug(f"Non-robust mode - binary_message: {binary_message}")
            
            string_message = getBitStringToString(binary_message)
            logger.info(f"Final decoded message: {repr(string_message)}")

        elif encoding_method.startswith("ext"):
            if robust:
                rob_timestamp = time.time()
                for pckCount in range(0, 19):
                    if (getSniffedHash(pckCount, 0)).time <= (rob_timestamp - robustignore):
                        binary_message = getSniffedHash(pckCount, 0)
                        break
            else:
                binary_message = getSniffedHash(0, 0)
            binary_message_int = list(map(int, binary_message))
            binary_message_without_cs = revertBitFlip(binary_message_int)
            string_message = getBitStringToString("".join(str(x) for x in binary_message_without_cs))

        elif encoding_method.startswith("ECC"):
            if robust:
                rob_timestamp = time.time()
                for pckCount in range(0, 19):
                    if (getSniffedHash(pckCount, 0)).time <= (rob_timestamp - robustignore):
                        binary_message = getSniffedHash(pckCount, 0)
                        break
            else:
                binary_message = getSniffedHash(0, 0)
            string_message = getBinaryToString_BCH(binary_message)

        logger.info(f"Writing message to file: {repr(string_message)}")
        
        try:
            with open(logfile_received_message, 'a', encoding='utf-8', errors='replace') as file_received_message:
                file_received_message.write(string_message)
            logger.info("Successfully wrote message to file")
        except Exception as e:
            logger.error(f"Error writing to file: {e}")
            
    elif isPktOfInterest(packet):
        latest_timestamp_cr_only = time.time() + timeslice_delay
        timestamp = time.time() + timeslice_delay
        critical_fraction, seconds = math.modf(timestamp)
        input1 = getInputValues(packet)
        hash_val = getHashValue(input1)
        
        # Handle critical fractions consistently
        if (critical_fraction > crit_fraction_high or critical_fraction < crit_fraction_low):
            logger.debug(f"CR: Critical fraction detected: {critical_fraction}")
            DB.appendleft("")
        else:
            logger.debug(f"CR: Adding hash to DB at critical_fraction: {critical_fraction}")
            DB.appendleft(hash_val)
            
        if robust:
            DBtime.appendleft(packet.time)
            
        with open(logfile_percentCoverage_covertMessage, 'a') as log:
            try:
                sniffed_hash_for_log = getSniffedHash(0, 0)
                log.write(str(latest_timestamp_cr_only) + ";" + str(sniffed_hash_for_log) + '\n')
            except Exception as e:
                logger.error(f"Error writing to log: {e}")
                log.write(str(latest_timestamp_cr_only) + ";" + "ERROR" + '\n')

if sys.argv[1] == "--help" or sys.argv[1] == "-h":
    print("Usage:")
    print("DYST.py <Covert Message File> <# of bytes at once> <interface> <logfile> <mode [cs,cr]> <coding method [trivial, trivial_robust, ext, ext_robust, ECC(experimental)]> "
          "<ARP Broadcast Target IP> <CR: ARP Broadcast Source IP> <CR: message logging file>")
    exit(100)

print("========Loading configuration=========")
covert_message_file = sys.argv[1]
number_of_chars = int(sys.argv[2])
interface = sys.argv[3]
logfile_percentCoverage_covertMessage = sys.argv[4]
mode = sys.argv[5]
hwv4_broadcast = "ff:ff:ff:ff:ff:ff"
ipv4_broadcast = "10.0.0.0" #str(netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['broadcast'])
hwv6_broadcast = "33:33"
ipv6_broadcast = "ff0"
signal_ipv6 = "fe80::1:1"
timeslice_delay = 0.007
encoding_method = sys.argv[6]
signal_arp = sys.argv[7]
signal_arp_from = ""
robust = False
oldPkt = None
timer = None
ba_save = None
robustdelay = 0.0
robustignore = 0.0
if mode == 'cr':
    signal_arp_from = sys.argv[8]
    logfile_received_message = sys.argv[9]
targetCount = 2
crit_fraction_high = 0.95
crit_fraction_low = 0.05

print("========Reading Covert Message=========")
covert_message = open(covert_message_file, 'r').read()
cm_array_current = 0
cm_array = [covert_message[i:i+number_of_chars] for i in range(0, len(covert_message), number_of_chars)]
if encoding_method.startswith("trivial"):
    ba_curr = getStringToBinary(cm_array[cm_array_current])
elif encoding_method.startswith("ext"):
    ba_temp = getStringToBinary(cm_array[cm_array_current])
    ba_curr = ba_temp + getCheckSum(ba_temp)
    masks = getMask(len(list(ba_curr)), len(list(ba_curr)) - targetCount)
elif encoding_method.startswith("ECC"):
    ba_curr = getStringToBinary_BCH(cm_array[cm_array_current])
else:
    print("Encoding method must either be 'trivial', 'ext' or 'ECC' -> exiting")
    exit(1)

if encoding_method.endswith("robust"):
    robust = True
    robustdelay = 0.5
    robustignore = 0.3
    timer = RepeatingTimer(robustdelay, sendARP, signal_arp)

logger.info(f"Configuration loaded - Mode: {mode}, Encoding: {encoding_method}")
logger.info(f"ba_curr initialized: {ba_curr[:50]}..." if len(ba_curr) > 50 else f"ba_curr: {ba_curr}")

print("========Starting Sniffing=========")
if mode == 'cs':
    sniff(iface=interface, prn=cs_sniffing)
elif mode == 'cr':
    sniff(iface=interface, prn=cr_sniffing)