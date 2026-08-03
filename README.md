# Secure Embedded Communication Framework (SECF) for RISC-V

An ultra-low latency, hardware-aware security framework designed for embedded systems and RISC-V architectures. SECF delivers robust confidentiality, integrity, and anti-replay protection using **AES-256-GCM** while maintaining real-time communication performance.

---

## 📌 Project Architecture

SECF provides a modular architecture comparing an **Insecure Baseline** pipeline against a **Secure Hardened** pipeline with integrated Man-in-the-Middle (MITM) attack simulation and real-time TUI profiling.

```text
+-------------------------------------------------+
|                 Node A (Sender)                 |
|               AES-256-GCM Encrypt               |
+------------------------+------------------------+
                         |
            [ Encrypted Packet Payload ]
                         |
      +------------------+------------------+
      |                                     |
      v                                     v
+------------------------+        +------------------------+
|    MITM Interceptor    |        |   Node B (Receiver)    |
|   Payload Tampering    +------->|    MAC Verification    |
|    Replay Injection    |        |   Replay Protection    |
+------------------------+        +------------------------+


---
```

## ⚡ Key Performance Metrics

| Performance Metric | Insecure Baseline | Secure Hardened (Active) | Ideal Benchmark Target |
| :--- | :---: | :---: | :---: |
| **Connection Establishment** | 1.2 ms | **1.8 ms** | `< 2.0 ms` |
| **End-to-End Latency** | 0.0024 ms | **0.0028 ms (2.8 µs)** | `< 0.0050 ms (5.0 µs)` |
| **Throughput** | 699,112 FPS | **592,468 FPS** | `> 100,000 FPS` |
| **Packet Delivery Ratio (PDR)**| 100.00% | **100.00%** | `100.00%` |
| **Retransmission Count** | 0 | **0** | `0` |
| **Protocol Overhead** | 0% | **+18.00%** | `< +25.00%` |

---

## 📂 Repository Structure

```text
.
├── packet.h                        # Struct definitions for secure payload & header
├── packet_utils.py                 # Packet serialization and parsing utilities
├── sender.c                        # Unencrypted baseline sender implementation
├── receiver.c                      # Unencrypted baseline receiver implementation
├── hardened_sender.c               # AES-256-GCM hardened transmitter
├── hardened_receiver.c             # AES-256-GCM receiver with MAC & sequence checking
├── Bench_crypto.c                  # Hardware micro-benchmarking engine (OpenSSL C)
├── Benchmarking_suite.py           # Automated benchmarking & normalization tool
├── Live_dashboard.py               # Real-time Terminal User Interface (TUI) dashboard
├── attack_simulation_dashboard.py  # Interactive MITM attack visualization engine
├── mitm_orchestrator.py            # Baseline MITM proxy & packet interceptor
├── Secure_mitm_orchestrator.py     # Hardened pipeline MITM resilience validator
└── stream_parser.py                # Telemetry parser for real-time profiling


---
```

## 🛠️ Prerequisites & Installation

### System Dependencies
Ensure your Linux environment (Native or VM) has standard GCC tools and OpenSSL development header files installed:

```bash
Bash
sudo apt update
sudo apt install build-essential libssl-dev python3 python3-pip python3-venv -y
```
### Virtual Environment Setup
```text
Bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install required Python TUI library
pip install rich
```

### 🚀 Usage & Workflows
### 1. Compile C Core Binaries
Compile the cryptographic benchmark and hardened node sources:
```text
Bash
gcc -O2 -o bench_crypto Bench_crypto.c -lssl -lcrypto -lm
gcc -O2 -o hardened_sender hardened_sender.c -lssl -lcrypto
gcc -O2 -o hardened_receiver hardened_receiver.c -lssl -lcrypto
```

### 2. Run Hardware Cryptographic Benchmark
Execute the automated benchmarking suite to generate benchmark_results.json:
```text
Bash
python3 Benchmarking_suite.py
```

3. Launch Live Performance Dashboard
Run the real-time profiling dashboard:
```text
Bash
python3 Live_dashboard.py
```
4. Execute MITM Attack Simulation
To test packet integrity and replay attack prevention under active tampering:
```text
Bash
# Launch attack orchestrator dashboard
python3 attack_simulation_dashboard.py
```

### 🛡️ Security Features
### AEAD Confidentiality & Integrity: 
Uses AES-256-GCM to simultaneously encrypt packet payloads and derive 128-bit authentication tags (MAC).

### Anti-Replay Protection: 
Maintains monotonic sequence counter tracking to discard duplicate or out-of-order replayed frames instantly.

### Low Latency Overhead: 
Employs OpenSSL context reuse and static buffer management to keep cryptography overhead capped at +18%.
