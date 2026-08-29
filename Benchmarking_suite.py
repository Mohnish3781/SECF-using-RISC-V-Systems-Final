#!/usr/bin/env python3
import serial
import json
import re

SERIAL_PORT = "/dev/ttyUSB0"
BAUD_RATE = 115200

def capture_hardware_benchmarks():
    print(f"[*] Listening on {SERIAL_PORT} for ESP32 hardware benchmark results...")
    
    try:
        ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=10)
    except Exception as e:
        print(f"[-] Could not open serial port: {e}")
        return

    results = {}
    
    try:
        while True:
            line = ser.readline().decode('utf-8', errors='ignore').strip()
            if not line:
                continue
            
            print(f"ESP32: {line}")
            
            # Match output from Bench_crypto_2.c
            match = re.search(r"took (\d+) us", line)
            if match:
                total_us = int(match.group(1))
                per_op_us = total_us / 10000.0
                results["hardware_aes_gcm_latency_us"] = per_op_us
                
                with open("benchmark_results.json", "w") as f:
                    json.dump(results, f, indent=4)
                print(f"[+] Benchmark logged successfully. Avg per op: {per_op_us} us")
                break
                
    except KeyboardInterrupt:
        pass
    finally:
        ser.close()

if __name__ == "__main__":
    capture_hardware_benchmarks()
