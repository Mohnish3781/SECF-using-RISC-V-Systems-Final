#!/usr/bin/env python3
import time
import random
from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.console import Console

# --- Global state variables for live simulation ---
sequence_num = 6800
latency_hard = 0.0435
throughput_base = 70000
throughput_hard = 24100
pdr_hard = 99.94
retrans_count = 3

def generate_dashboard() -> Layout:
    """Generates the current frame of the dashboard layout."""
    global sequence_num, latency_hard, throughput_base, throughput_hard, pdr_hard, retrans_count

    # 1. Simulate data changing (similar to the video)
    sequence_num += random.randint(10, 50)
    latency_hard = random.uniform(0.0410, 0.0490)
    throughput_base = random.randint(69990, 70150)
    throughput_hard = random.randint(24100, 24800)
    pdr_hard = random.uniform(99.90, 100.00)
    retrans_count = random.choice([0, 1, 3, 5])
    
    # Generate fake live ciphertext
    hex_bytes = " ".join(f"{random.randint(0, 255):02X}" for _ in range(24)) + "..."

    # 2. Define the main layout grid
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="nodes", size=7),
        Layout(name="profiling"),
        Layout(name="footer", size=3)
    )
    layout["nodes"].split_row(
        Layout(name="node_a"),
        Layout(name="node_b")
    )

    # 3. Header Panel
    layout["header"].update(Panel(
        Text("🔒 SECURE EMBEDDED COMMUNICATION DASHBOARD 🔒", justify="center", style="bold white"), 
        border_style="magenta"
    ))

    # 4. Node A Panel (Sender)
    node_a_text = Text()
    node_a_text.append("Node State:\t\t", style="white")
    node_a_text.append("TRANSMITTING\n", style="bold cyan")
    node_a_text.append("Encryption:\t\t", style="white")
    node_a_text.append("AES-256-GCM ACTIVE\n", style="bold green")
    node_a_text.append("Current Sequence:\t", style="white")
    node_a_text.append(f"{sequence_num}", style="bold yellow")
    
    layout["node_a"].update(Panel(
        node_a_text, 
        title="📡 NODE A (SENDER)", 
        border_style="magenta", 
        title_align="left"
    ))

    # 5. Node B Panel (Receiver)
    node_b_text = Text()
    node_b_text.append("Node State:\t\t", style="white")
    node_b_text.append("LISTENING\n", style="bold cyan")
    node_b_text.append("MAC Verification:\t", style="white")
    node_b_text.append("✅ VALID\n", style="bold green")
    node_b_text.append("Replay Protection:\t", style="white")
    node_b_text.append("✅ SEQ ACCEPTED", style="bold green")
    
    layout["node_b"].update(Panel(
        node_b_text, 
        title="📡 NODE B (RECEIVER)", 
        border_style="magenta", 
        title_align="left"
    ))

    # 6. Profiling Table
    table = Table(box=box.SIMPLE_HEAVY, expand=True, border_style="magenta")
    table.add_column("Performance Metric", style="bold white", width=35)
    table.add_column("Insecure Baseline", justify="center", style="bold white")
    table.add_column("Secure Hardened (Active)", justify="center", style="bold white")

    table.add_row("Connection Establishment Time", "8.5 ms", "12.4 ms")
    table.add_row("End-to-End Latency", "0.0143 ms", f"{latency_hard:.4f} ms")
    table.add_row("Throughput", f"{throughput_base:,} FPS", f"{throughput_hard:,} FPS")
    table.add_row("Packet Delivery Ratio (PDR)", "100.00%", f"{pdr_hard:.2f}%")
    table.add_row("Retransmission Count", "0", f"{retrans_count}")
    table.add_row("Protocol Overhead", "0%", "[bold red]+186%[/bold red]")

    layout["profiling"].update(Panel(
        table, 
        title="📊 LIVE COMMUNICATION PERFORMANCE PROFILING (OPTION 2)", 
        border_style="magenta"
    ))

    # 7. Footer Panel (Ciphertext Intercept)
    layout["footer"].update(Panel(
        f"Live Ciphertext Intercept: [bold white]{hex_bytes}[/bold white]", 
        border_style="magenta"
    ))

    return layout

if __name__ == "__main__":
    console = Console()
    console.clear()
    
    # Run the live dashboard loop
    try:
        # Refresh 10 times per second for a smooth "live" feel
        with Live(generate_dashboard(), refresh_per_second=10, screen=True) as live:
            while True:
                time.sleep(0.1)
                live.update(generate_dashboard())
    except KeyboardInterrupt:
        console.print("[bold red]Dashboard terminated by user.[/bold red]")
