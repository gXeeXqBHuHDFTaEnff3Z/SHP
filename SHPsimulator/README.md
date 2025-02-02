# SHPsimulator

## Overview

**SHPsimulator** is a Python-based simulator for analyzing and processing covert network communication via the **Silent History Protocol (SHP)**. The tool is designed to process PCAP and PCAPNG files, extracting timing information from **packets of interest (POI)** to evaluate network-history-based covert channels. The simulator facilitates controlled experimentation with various parameters, including packet timing, error correction, subchanneling, and covert signal amplification.

This project is based on research outlined in the paper *"Silence Speaks Volumes: A New Paradigm for Covert Communication via Network-History Timing Patterns"* by Christoph Weissenborn and Steffen Wendzel.

## Features

- Parses PCAP/PCAPNG network capture files
- Implements **Silent History Protocol (SHP)** for covert communication analysis
- Supports **error correction codes (ECC)**: Hamming, Hamming+, Inline-Hamming+
- Allows **timing-based covert communication simulation**
- Supports **subchanneling** for better entropy in timing-based encoding
- Configurable **out-of-order delivery (OOOD)** and **rehashing** for improved signal reliability
- Logs detailed simulation statistics, including signal match rate, bandwidth, and covert amplification factor

## Installation

### Prerequisites
Ensure you have Python 3.x installed on your system. Install dependencies using the provided requirements file:

```bash
pip install -r SHPsimulator_requirements.txt
```

The following Python packages are required:

- `scapy`
- `numpy`
- `scipy`
- `argparse`
- `csv`
- `logging`
- `datetime`
- `random`

## Usage

Run the script using the following command:

```bash
python SHPsimulator.py --capfolder <path_to_pcaps> --poi <all|broadcast|port> --inputsource <source_type> --bitlength <num_bits>
```

### Arguments and Options

#### **Packet Filtering Parameters:**
| Option                | Description |
|----------------------|-------------|
| `--mode_filter`       | Packet filtering mode (`bpf` by default) |
| `--poi`              | Packet of Interest type (`all`, `broadcast`, `port`) |
| `--silence`          | Silence interval (milliseconds) [0-10000] |

#### **SHP-Specific Parameters:**
| Option                 | Description |
|----------------------|-------------|
| `--bitlength`         | Number of bits to compare per message chunk |
| `--inputsource`       | Source of timing input (`IPD`, `ISD`, `timestamp`, etc.) |
| `--timing_window`     | Time window for rounding timestamps [1-1000] |
| `--subchanneling`     | Subchanneling mode (`none`, `baseipd`, etc.) |
| `--subchanneling_bits`| Number of bits for subchannel selection [0-n] |
| `--rehash`           | Number of times to hash the input data for better matching |
| `--out-of-order-delivery` | Allows sending ahead and reordering chunks [0-n] |
| `--ecc`              | Error correction mode (`none`, `hamming`, `hamming+`, `inline-hamming+`) |

#### **Simulation Parameters:**
| Option             | Description |
|------------------|-------------|
| `--saveWithPointer` | Saves POI to a pcapng file, adding an ARP pointer for each match |
| `--batching`       | Enables batch processing for large PCAP files |
| `--packetloss_percentage` | Simulates packet loss percentage [0-100] |
| `--packetdelay`    | Simulates network delay in milliseconds |
| `--packetjitter`   | Simulates jitter variation |
| `--simulateCR`     | Simulates Covert Receiver message decoding |
| `--verbose`        | Enables detailed logging and CSV output |

#### **Statistics & Performance:**
| Option              | Description |
|--------------------|-------------|
| `--path_file_results` | Path to save the results CSV file |
| `--comment_field`   | Comment field for tagging the experiment |
| `--rounding_factor` | Rounds timing data for entropy balancing |

## Example Commands

1. **Basic Execution:**
```bash
python SHPsimulator.py --capfolder ./captures/ --poi port --inputsource IPD --bitlength 8
```

2. **Advanced Simulation with ECC and Jitter Simulation:**
```bash
python SHPsimulator.py --capfolder ./captures/ --poi all --inputsource timestamp --bitlength 16 --ecc hamming --packetloss_percentage 5 --packetjitter 3 --simulateCR
```

3. **Saving POI with Pointer Insertion:**
```bash
python SHPsimulator.py --capfolder ./captures/ --poi broadcast --bitlength 8 --saveWithPointer
```

## Output

### **Summary File:**
The results will be saved in `SHPsim_summary.csv` containing the following data:
- Processing runtime, cache hitrate, total bytes/packets processed
- POI matches, signal matches, covert amplification factor (CAF)
- Estimated bandwidth (bps), covert transmission efficiency

### **Detailed Logs:**
If `--verbose` is enabled, a CSV file with per-packet match details will be created in the results folder.

## References
This simulator is based on the research from:
- *Silence Speaks Volumes: A New Paradigm for Covert Communication via Network-History Timing Patterns* by Christoph Weissenborn & Steffen Wendzel

## License
This project is released under the MIT License. See `LICENSE` for details.

---

For any questions or contributions, feel free to open an issue or pull request on GitHub.

