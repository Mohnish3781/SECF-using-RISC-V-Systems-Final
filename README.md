# Secure Embedded Communication Framework (SECF) for RISC-V / ESP32

An ultra-low latency, hardware-aware security framework designed for embedded systems. SECF delivers robust confidentiality, integrity, and anti-replay protection using **ESP32 Hardware Accelerated AES-256-GCM** while maintaining real-time UART serial communication performance.

---

## 📌 Hardware Project Architecture

SECF provides a modular architecture targeting physical ESP32 boards, utilizing `pyserial` to create an orchestrator between hardware nodes.

```text
+-------------------------------------------------+
|              Node A (ESP32 Sender)              |
|        mbedTLS AES-256-GCM Encrypt (UART)       |
+------------------------+------------------------+
                         |
            [ Serial Encrypted Payload ]
                         |
      +------------------+------------------+
      |                                     |
      v                                     v
+------------------------+        +------------------------+
| Python PC Interceptor  |        | Node B (ESP32 Receiver)|
|   PySerial Tampering   +------->| UART MAC Verification  |
|    Replay Injection    |        |   Replay Protection    |
+------------------------+        +------------------------+
