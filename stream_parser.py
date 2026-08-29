#!/usr/bin/env python3
import sys
import struct
import binascii
import serial
import time

# Hardware USB mappings replace /tmp/ pipes
SERIAL_PORT = "/dev/ttyUSB0"
BAUD_RATE = 115200

HEADER_FORMAT = '<IBBBxH'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  
REMAINDER_SIZE = 262

def execute_two_phase_parser():
    print("[*] Initializing Phase 2 / Week 3 Parsing Engine (Hardware ESP32 Compatible)...")
    print(f"[*] Opening hardware serial link on {SERIAL_PORT} @ {BAUD_RATE} baud...")
    
    try:
        ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=None)
        print("[+] Hardware Link established! Reading binary stream sequentially.\n")
    except serial.SerialException as e:
        print(f"[-] Serial port error: {e}")
        sys.exit(1)

    try:
        while True:
            # Phase 1: Header Block read via PySerial
            raw_header = ser.read(HEADER_SIZE)
            
            if not raw_header or len(raw_header) < HEADER_SIZE:
                continue

            magic, src_id, dest_id, packet_type, payload_len = struct.unpack(HEADER_FORMAT, raw_header)
            
            print("┌" + "─"*60)
            print(f"│ [PHASE 1 SUCCESS] Extracted Header Block Telemetry")
            print(f"│  ├── Magic Signature   : {hex(magic).upper()}")
            print(f"│  ├── Source Node ID    : {src_id}")
            print(f"│  ├── Destination ID    : {dest_id}")
            print(f"│  ├── Packet Type Tag   : {packet_type}")
            print(f"│  └── Dynamic Payload   : {payload_len} bytes calculated")
            print("├" + "─"*60)

            # Phase 2: Payload and Checksums via PySerial
            raw_phase2_block = ser.read(REMAINDER_SIZE)
            
            if len(raw_phase2_block) < REMAINDER_SIZE:
                print("[-] Warning: Remainder stream truncation detected. Dropping frame.")
                print("└" + "─"*60 + "\n")
                continue
            
            raw_payload_array = raw_phase2_block[:256]
            raw_payload_body = raw_payload_array[:payload_len]
            
            packet_checksum, sequence_counter = struct.unpack('<HI', raw_phase2_block[256:262])
            
            local_arithmetic_checksum = sum(raw_payload_body) & 0xFFFF
            local_crc32 = binascii.crc32(raw_payload_body)
            decoded_message = raw_payload_body.decode('utf-8', errors='ignore')

            print(f"│ [PHASE 2 SUCCESS] Extracted Remainder Data Blocks")
            print(f"│  ├── String Body       : \"{decoded_message}\"")
            print(f"│  ├── Stream Checksum   : {packet_checksum} (Local Calc: {local_arithmetic_checksum})")
            print(f"│  ├── Local CRC32 Tag   : {hex(local_crc32).upper()}")
            print(f"│  └── Sequence Index    : {sequence_counter}")
            print("└" + "─"*60 + "\n")

    except KeyboardInterrupt:
        print("\n[*] Parsing engine closed manually by engineer interrupt.")
    finally:
        ser.close()
        print("[*] Serial port resource handle closed successfully.")

if __name__ == "__main__":
    execute_two_phase_parser()
