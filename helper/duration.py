import os
import sys
import datetime
from scapy.all import rdpcap, PcapReader

def get_pcap_duration(pcap_file):
    """
    Calculate the duration of a pcap/pcapng file (time between first and last packet)
    Returns a tuple of (duration_in_seconds, first_datetime, last_datetime, packet_count)
    """
    try:
        # Open the pcap file with scapy
        with PcapReader(pcap_file) as packets:
            # Get first packet
            first_packet = next(packets)
            first_time = float(first_packet.time)
            
            # To find the last packet, we need to iterate through all packets
            # Initialize last_time with first_time
            last_time = first_time
            
            # Count packets for reporting
            packet_count = 1
            
            # Continue reading all packets to find the last one
            for packet in packets:
                last_time = float(packet.time)
                packet_count += 1
        
        # Calculate duration
        duration_seconds = last_time - first_time
        
        # Convert timestamps to readable format
        first_datetime = datetime.datetime.fromtimestamp(first_time)
        last_datetime = datetime.datetime.fromtimestamp(last_time)
        
        return (duration_seconds, first_datetime, last_datetime, packet_count)
    
    except Exception as e:
        return (f"Error processing file: {str(e)}", None, None, 0)

def format_duration(seconds):
    """Format duration in seconds to a readable string (HH:MM:SS.microseconds)"""
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{int(hours):02d}:{int(minutes):02d}:{seconds:.6f}"

def truncate_filename(filename, max_length=30):
    """Truncate filename if longer than max_length, adding ellipsis in the middle"""
    if len(filename) <= max_length:
        return filename
    
    # Keep the extension and some of the beginning/end
    extension = os.path.splitext(filename)[1]
    keep_end = min(len(extension) + 10, len(extension) + max_length//4)
    keep_start = max_length - keep_end - 3  # 3 for the ellipsis
    
    return filename[:keep_start] + "..." + filename[-keep_end:]

def calculate_packets_per_second(packet_count, duration_seconds):
    """Calculate packets per second, handling edge cases"""
    if duration_seconds <= 0:
        return "N/A"  # Avoid division by zero
    return f"{packet_count / duration_seconds:.2f}"

def main():
    # Change working directory to the directory the script is in
    script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    os.chdir(script_dir)
    
    print("PCAP File Duration Analysis")
    print(f"Working directory: {script_dir}")
    print("=" * 110)
    print(f"{'Filename':<32} {'Duration':<15} {'Packets':<10} {'Packets/s':<10} {'Start Time':<22} {'End Time':<22}")
    print("-" * 110)
    
    # Get all pcap/pcapng files in the script's directory
    pcap_files = [f for f in os.listdir('.') if f.endswith(('.pcap', '.pcapng'))]
    
    if not pcap_files:
        print("No pcap or pcapng files found in the script's directory.")
        return
    
    for pcap_file in sorted(pcap_files):
        try:
            print(f"Processing {pcap_file}...", end='\r')
            result = get_pcap_duration(pcap_file)
            
            if isinstance(result[0], str):  # Error occurred
                print(f"{truncate_filename(pcap_file, 32):<32} {result[0]}")
            else:
                duration, start_time, end_time, packet_count = result
                duration_str = format_duration(duration)
                start_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
                end_str = end_time.strftime("%Y-%m-%d %H:%M:%S")
                packets_per_second = calculate_packets_per_second(packet_count, duration)
                
                print(f"{truncate_filename(pcap_file, 32):<32} {duration_str:<15} {packet_count:<10} {packets_per_second:<10} {start_str:<22} {end_str:<22}")
        except Exception as e:
            print(f"{truncate_filename(pcap_file, 32):<32} Error: {str(e)}")

if __name__ == "__main__":
    main()