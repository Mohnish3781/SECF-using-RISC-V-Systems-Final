#!/usr/bin/env python3
"""
IITI SOC 2026 - PS8: Secure Embedded Communication Framework
BENCHMARKING SUITE - Protocol Hardening & Performance Engineering
"""

import os
import subprocess
import json
import sys
from datetime import datetime

BENCH_C_SOURCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bench_crypto.c")
BENCH_BINARY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bench_crypto")

NUM_PACKETS_THROUGHPUT = 1000

def compile_bench_crypto():
    """Compile bench_crypto.c (requires gcc + OpenSSL dev headers)."""
    cmd = ["gcc", "-O2", "-o", BENCH_BINARY, BENCH_C_SOURCE, "-lssl", "-lcrypto", "-lm"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("[-] Compilation failed:")
        print(result.stderr)
        sys.exit(1)

def run_bench_crypto():
    """Run the compiled benchmark binary and parse its JSON output."""
    result = subprocess.run([BENCH_BINARY], capture_output=True, text=True)
    if result.returncode != 0:
        print("[-] bench_crypto execution failed:")
        print(result.stderr)
        sys.exit(1)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print("[-] Could not parse bench_crypto output as JSON:", e)
        sys.exit(1)

def print_summary(results):
    """Print benchmark summary in the requested tabular format."""
    print("\n\n" + "="*70)
    print("📈 PERFORMANCE OVERHEAD ANALYSIS")
    print("="*70)
    
    header = f"| {'Metric':<25} | {'Insecure Baseline':<20} | {'Secure Hardened':<20} |"
    divider = f"|{'-'*27}|{'-'*22}|{'-'*22}|"
    
    print(header)
    print(divider)
    
    # Packets Per Second
    pps_base = f"{results['throughput']['baseline']['packets_per_second']:.2f} pkts/sec"
    pps_sec = f"{results['throughput']['hardened']['packets_per_second']:.2f} pkts/sec"
    print(f"| {'Throughput (PPS)':<25} | {pps_base:<20} | {pps_sec:<20} |")
    
    # Average Latency (Convert microseconds to milliseconds)
    lat_base = f"{results['latency']['baseline']['mean_us'] / 1000.0:.4f} ms"
    lat_sec = f"{results['latency']['hardened']['mean_us'] / 1000.0:.4f} ms"
    print(f"| {'Average Round-Trip Latency':<25} | {lat_base:<20} | {lat_sec:<20} |")
    
    # Maximum Jitter (Using standard deviation converted to milliseconds)
    jit_base = f"{results['jitter']['baseline_stdev_us'] / 1000.0:.4f} ms"
    jit_sec = f"{results['jitter']['hardened_stdev_us'] / 1000.0:.4f} ms"
    print(f"| {'Maximum Jitter':<25} | {jit_base:<20} | {jit_sec:<20} |")
    print("-" * 70)
    
    overhead = results['latency']['overhead_percent']
    print(f"\n[!] Cryptographic Overhead Imposed: +{overhead:.2f}% latency per packet.")

def run_comprehensive_benchmark():
    print("="*70)
    print("📊 IITI SOC 2026: END-TO-END PERFORMANCE BENCHMARKING (DOMAIN 4)")
    print("="*70)

    # Compile silently to keep the output clean
    compile_bench_crypto()
    
    # Run the C backend which handles the real crypto timings
    results = run_bench_crypto()
    results["timestamp"] = datetime.now().isoformat()

    # Simulate the visual run phases for output consistency
    print(f"\n[*] Initiating Profiling Run: INSECURE_BASELINE")
    print(f"[*] Pumping {NUM_PACKETS_THROUGHPUT} packets through the channel...")
    print(f"    └── Completed in {results['throughput']['baseline']['total_time_sec']:.4f} seconds.")

    print(f"\n[*] Initiating Profiling Run: SECURE_HARDENED")
    print(f"[*] Pumping {NUM_PACKETS_THROUGHPUT} packets through the channel...")
    print(f"    └── Completed in {results['throughput']['hardened']['total_time_sec']:.4f} seconds.")

    print_summary(results)

if __name__ == "__main__":
    run_comprehensive_benchmark()
