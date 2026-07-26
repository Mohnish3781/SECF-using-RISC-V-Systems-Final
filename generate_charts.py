#!/usr/bin/env python3

import matplotlib.pyplot as plt
import numpy as np
import os

# Data extracted exactly from the Phase 1 benchmark results
categories = ['Insecure Baseline', 'Secure Hardened']
throughput_pps = [70006.88, 24444.28]
latency_ms = [0.0143, 0.0409]
jitter_ms = [0.8059, 2.0025]

def generate_throughput_chart():
    """Generates a bar chart comparing Packets Per Second (PPS)."""
    plt.figure(figsize=(8, 6))
    
    # Create bars
    bars = plt.bar(categories, throughput_pps, color=['#e74c3c', '#2ecc71'], width=0.5)
    
    # Add titles and labels
    plt.title('Protocol Throughput Comparison (Packets Per Second)', fontsize=14, fontweight='bold', pad=15)
    plt.ylabel('Throughput (PPS)', fontsize=12, fontweight='bold')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Add exact value labels on top of the bars
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval + 1000, f"{yval:,.0f} PPS", ha='center', va='bottom', fontsize=11, fontweight='bold')
    
    # Save the figure
    plt.tight_layout()
    plt.savefig('throughput_comparison.png', dpi=300)
    print("[+] Saved throughput chart as 'throughput_comparison.png'")

def generate_latency_jitter_chart():
    """Generates a grouped bar chart comparing Latency and Jitter."""
    plt.figure(figsize=(9, 6))
    
    x = np.arange(len(categories))
    width = 0.35  # width of the bars
    
    # Create grouped bars
    bars1 = plt.bar(x - width/2, latency_ms, width, label='Average Latency (ms)', color='#3498db')
    bars2 = plt.bar(x + width/2, jitter_ms, width, label='Maximum Jitter (ms)', color='#f39c12')
    
    # Add titles and labels
    plt.title('Cryptographic Overhead: Latency & Jitter', fontsize=14, fontweight='bold', pad=15)
    plt.ylabel('Time (Milliseconds)', fontsize=12, fontweight='bold')
    plt.xticks(x, categories, fontsize=11, fontweight='bold')
    plt.legend(fontsize=11)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Add exact value labels on top of the bars
    for bar in bars1:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval + 0.05, f"{yval:.4f}", ha='center', va='bottom', fontsize=10)
        
    for bar in bars2:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval + 0.05, f"{yval:.4f}", ha='center', va='bottom', fontsize=10)
        
    # Annotate the overhead percentage
    plt.annotate(
        '+186% Latency Overhead\n(AES-GCM + Sequence Validation)', 
        xy=(1 - width/2, latency_ms[1]), 
        xytext=(0.5, 1.0), 
        arrowprops=dict(facecolor='black', shrink=0.05, width=1.5, headwidth=7),
        fontsize=10,
        fontweight='bold',
        bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="gray", lw=1)
    )

    # Save the figure
    plt.tight_layout()
    plt.savefig('latency_jitter_comparison.png', dpi=300)
    print("[+] Saved latency/jitter chart as 'latency_jitter_comparison.png'")

if __name__ == "__main__":
    print("="*60)
    print("📊 GENERATING MATPLOTLIB BENCHMARK VISUALIZATIONS")
    print("="*60)
    
    # Ensure matplotlib is installed
    try:
        import matplotlib
    except ImportError:
        print("[-] Matplotlib not found. Please run: pip3 install matplotlib numpy")
        exit(1)
        
    generate_throughput_chart()
    generate_latency_jitter_chart()
    
    print("\n[*] Phase 2 Complete. Charts are ready for the Technical Report.")
    print("="*60)
