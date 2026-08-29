#!/usr/bin/env python3
import serial
import struct
import argparse

SERIAL_PORT_IN = "/dev/ttyUSB0" 
SERIAL_PORT_OUT = "/dev/ttyUSB1"
BAUD_RATE = 115200

# Insecure packet format (No Nonce, Salt, or Tag)
INSECURE_FORMAT = "<IBBBHII256s" 
INSECURE_SIZE = struct.calcsize(INSECURE_FORMAT)

def run_insecure_proxy(mode):
    print(f"[*] Initializing INSECURE Baseline Proxy. Mode: [{mode.upper()}]")
    
    ser_in = serial.Serial(SERIAL_PORT_IN, BAUD_RATE)
    ser_out = serial.Serial(SERIAL_PORT_OUT, BAUD_RATE)
    print("[+] Hardware UART proxy routing engaged (Unencrypted Link).\n")

    try:
        while True:
            raw_packet = ser_in.read(INSECURE_SIZE)
            if len(raw_packet) < INSECURE_SIZE:
                continue

            (magic, ptype, src, dest, length, seq, ts, payload) = struct.unpack(INSECURE_FORMAT, raw_packet)

            print(f"[INTERCEPTED - INSECURE] Seq: {seq} | Payload: {payload[:length].decode('utf-8', 'ignore')}")

            if mode == "tamper":
                print("[!] Tampering plaintext payload directly!")
                mutated = bytearray(payload)
                mutated[0] = ord('X')
                raw_packet = struct.pack(INSECURE_FORMAT, magic, ptype, src, dest, length, seq, ts, bytes(mutated))

            ser_out.write(raw_packet)

    except KeyboardInterrupt:
        print("\n[*] Proxy shutdown.")
    finally:
        ser_in.close()
        ser_out.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["sniff", "tamper", "replay"], required=True)
    args = parser.parse_args()
    run_insecure_proxy(args.mode)
