# SHP Project Repository

## Overview

The **SHP Project** is a collection of tools and scripts designed to explore and implement the **Silent History Protocol (SHP)** for covert network communication. The project consists of:

- **SHPsimulator**: A Python script for offline processing and analysis of network-history covert channels using PCAP/PCAPNG files.
- **SHPlive**: A real-time server-client implementation of SHP, allowing covert communication over live network traffic.

This project is based on research outlined in the paper *"Silence Speaks Volumes: A New Paradigm for Covert Communication via Network-History Timing Patterns"* by Christoph Weissenborn and Steffen Wendzel.

---

## Repository Structure

```
SHP-Project/
│   README.md  (this file)
│   SHPsimulator/
│   ├── SHPsimulator.py
│   ├── SHPsimulator_requirements.txt
│   ├── results/
│   ├── captures/
│   ├── README.md
│
│   SHPlive/
│   ├── SHPserver.py
│   ├── SHPclient.py
│   ├── SHPlive_requirements.txt
│   ├── README.md
```

---

## SHPsimulator

SHPsimulator is a Python script for offline simulation and analysis of SHP-based covert communication. It processes packet capture files (PCAP/PCAPNG) to evaluate signal encoding efficiency, error correction, and timing-based communication strategies.

### **Installation & Usage**
Refer to the [`SHPsimulator/README.md`](SHPsimulator/README.md) for installation steps and usage examples.

---

## SHPlive (Live Networking Server & Client)

**SHPlive** provides a real-time implementation of the Silent History Protocol (SHP), enabling live covert communication between a **covert sender (CS)** and a **covert receiver (CR)** over an active network.

### **Features**
- Real-time packet capture and covert signaling
- Supports multiple input sources for timing-based encoding
- Packet jitter, delay, and packet loss simulation
- Encrypted signaling with optional error correction codes (ECC)
- Logs covert communication activity

### **Installation**
Ensure you have Python 3.x installed and install the required dependencies from the respective folders.

## Contributing

We welcome contributions to the project! Feel free to:
- Report issues
- Submit pull requests
- Suggest enhancements

For major contributions, please discuss your proposed changes by opening an issue first.

---

## References
This repository is based on the research from:
- *Silence Speaks Volumes: A New Paradigm for Covert Communication via Network-History Timing Patterns* by Christoph Weissenborn & Steffen Wendzel

---

## License
This project is released under the MIT License. See `LICENSE` for details.

For questions or contributions, feel free to open an issue or pull request on GitHub!

