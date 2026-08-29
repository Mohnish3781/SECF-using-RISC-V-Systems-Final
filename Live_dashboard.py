#!/usr/bin/env python3
"""
IITI SOC 2026 - Hardware Performance Dashboard
Reads physical ESP32 UART throughput via PySerial and renders a Rich TUI.
"""

import time
import serial
import struct
from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel

SERIAL_PORT = "/dev/ttyUSB1" # Monitoring the Receiver Node
BAUD_RATE = 115200

# 317-byte packed hardware frame
PACKET_FORMAT = "<IBBBHII12s16s16s256s"
PACKET_SIZE = struct.calcsize(PACKET_FORMAT)

def generate_table(packets_received, errors, throughput_bps):
    """Generates the Rich TUI table for hardware telemetry."""
    table = Table(title="ESP32 SECF Hardware Telemetry", style="cyan")
    table.add_column("Metric", justify="right", style="magenta")
    table.add_column("Value", justify="left", style="green")
    
    table.add_row("Link Interface", f"{SERIAL_PORT} @ {BAUD_RATE} baud")
    table.add_row("Total Packets RX", str(packets_received))
    table.add_row("Dropped / Errors", f"[red]{errors}[/red]" if errors > 0 else "0")
    table.add_row("Throughput", f"{throughput_bps:.2f} Bytes/sec")
    
    return Panel(table, title="Live Hardware Node B (Receiver)")

def run_dashboard():
    packets = 0
    errors = 0
    start_time = time.time()
    
    try:
        ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=0.1)
    except serial.SerialException as e:
        print(f"[!] Failed to connect to ESP32: {e}")
        return

    with Live(generate_table(0, 0, 0), refresh_per_second=4) as live:
        try:
            while True:
                raw_data = ser.read(PACKET_SIZE)
                if len(raw_data) == PACKET_SIZE:
                    packets += 1
                elif len(raw_data) > 0:
                    errors += 1 # Frame misalignment
                
                elapsed = time.time() - start_time
                bps = (packets * PACKET_SIZE) / elapsed if elapsed > 0 else 0
                
                live.update(generate_table(packets, errors, bps))
                
        except KeyboardInterrupt:
            pass
        finally:
            ser.close()

if __name__ == "__main__":
    run_dashboard()
