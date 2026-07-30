#!/usr/bin/env python3
"""
IITI SOC 2026 - PS8: Secure Embedded Communication Framework
BENCHMARKING SUITE - Protocol Hardening & Performance Engineering
Author: Abhinay Rathod (Member 4)
Purpose: Measure latency, throughput, jitter for baseline vs hardened protocol

METHODOLOGY NOTE (important for your report):
This script does NOT simulate timings with time.sleep(). It compiles and
runs bench_crypto.c, which times the ACTUAL OpenSSL AES-256-GCM and
HMAC-SHA256 calls used by your hardened_sender/receiver, via
clock_gettime(CLOCK_MONOTONIC). Baseline numbers reflect a genuine
no-crypto memcpy path over the same payload size, so the comparison is
apples-to-apples with your real code, not an assumed constant.
"""

import os
import subprocess
import json
import sys
from datetime import datetime

BENCH_C_SOURCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bench_crypto.c")
BENCH_BINARY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bench_crypto")


def compile_bench_crypto():
    """Compile bench_crypto.c (requires gcc + OpenSSL dev headers)."""
    print("[*] Compiling bench_crypto.c (real AES-256-GCM / HMAC-SHA256 timing harness)...")
    cmd = ["gcc", "-O2", "-o", BENCH_BINARY, BENCH_C_SOURCE, "-lssl", "-lcrypto", "-lm"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("[-] Compilation failed:")
        print(result.stderr)
        print("\n[!] Make sure OpenSSL dev headers are installed:")
        print("    sudo apt install -y build-essential libssl-dev   (on WSL/Ubuntu)")
        sys.exit(1)
    print("[+] Compiled successfully.\n")


def run_bench_crypto():
    """Run the compiled benchmark binary and parse its JSON output."""
    print("[*] Running real benchmark (100 latency samples, 1000 throughput packets,")
    print("    1000 AES/HMAC overhead iterations, 100000 sequence-check iterations)...\n")
    result = subprocess.run([BENCH_BINARY], capture_output=True, text=True)
    if result.returncode != 0:
        print("[-] bench_crypto execution failed:")
        print(result.stderr)
        sys.exit(1)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print("[-] Could not parse bench_crypto output as JSON:", e)
        print(result.stdout)
        sys.exit(1)

# =====================================================
# CONFIGURATION
# =====================================================

PACKET_SIZE = 512  # bytes (estimated for hardened packet)
NUM_PACKETS_LATENCY = 100  # packets for latency test
NUM_PACKETS_THROUGHPUT = 1000  # packets for throughput test
PIPE_BASELINE_IN = "/tmp/nodeA_to_attacker"
PIPE_HARDENED_IN = "/tmp/secure_nodeA_to_attacker"

# =====================================================
# LATENCY MEASUREMENT
# =====================================================

def run_comprehensive_benchmark():
    """Compile bench_crypto.c, run it, and package/print the real results."""

    print("\n" + "="*70)
    print("IITI SOC 2026 - PS8: COMPREHENSIVE PERFORMANCE BENCHMARK (REAL)")
    print("="*70)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)

    compile_bench_crypto()
    results = run_bench_crypto()
    results["timestamp"] = datetime.now().isoformat()

    print(f"Payload size: {results.get('payload_size_bytes')} bytes")
    print(f"Methodology: {results.get('methodology')}\n")

    # --- PRINT SUMMARY ---
    print_summary(results)

    # Save JSON results
    save_results_json(results)

    return results


# =====================================================
# REPORTING
# =====================================================

def print_summary(results):
    """Print benchmark summary"""
    
    print("\n" + "="*70)
    print("BENCHMARK RESULTS SUMMARY")
    print("="*70)
    
    # Latency Summary
    print("\n[LATENCY ANALYSIS]")
    print(f"  Baseline Mean Latency : {results['latency']['baseline']['mean_us']:.4f} µs")
    print(f"  Hardened Mean Latency : {results['latency']['hardened']['mean_us']:.4f} µs")
    print(f"  Overhead             : {results['latency']['overhead_percent']:.2f}%")
    print(f"  Baseline p95         : {results['latency']['baseline']['p95_us']:.4f} µs")
    print(f"  Hardened p95         : {results['latency']['hardened']['p95_us']:.4f} µs")
    
    # Throughput Summary
    print("\n[THROUGHPUT ANALYSIS]")
    print(f"  Baseline Packets/sec : {results['throughput']['baseline']['packets_per_second']:.2f} pps")
    print(f"  Hardened Packets/sec : {results['throughput']['hardened']['packets_per_second']:.2f} pps")
    print(f"  Throughput Reduction : {results['throughput']['reduction_percent']:.2f}%")
    print(f"  Baseline Mbps        : {results['throughput']['baseline']['mbps']:.4f} Mbps")
    print(f"  Hardened Mbps        : {results['throughput']['hardened']['mbps']:.4f} Mbps")
    
    # Overhead Summary
    print("\n[PER-MECHANISM OVERHEAD]")
    for key, value in results['overhead'].items():
        if key != 'total_crypto_overhead_us':
            print(f"  {value['mechanism']:<40} : {value['avg_time_us']:.4f} µs")
    print(f"  Total Crypto Overhead for 256B : {results['overhead']['total_crypto_overhead_us']:.4f} µs")
    
    # Jitter Summary
    print("\n[JITTER ANALYSIS]")
    print(f"  Baseline Jitter (σ)  : {results['jitter']['baseline_stdev_us']:.4f} µs")
    print(f"  Hardened Jitter (σ)  : {results['jitter']['hardened_stdev_us']:.4f} µs")
    
    print("\n" + "="*70)


def save_results_json(results):
    """Save results to JSON file (next to this script)"""
    output_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmark_results.json")
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Results saved to: {output_file}")


if __name__ == "__main__":
    results = run_comprehensive_benchmark()
