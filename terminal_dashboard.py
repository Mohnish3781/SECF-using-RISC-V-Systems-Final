import time
import random
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich import box
from rich.text import Text
from rich.align import Align

def generate_hex_string(length=32):
    """Generates a random hex string to simulate ciphertext intercept."""
    return " ".join([f"{random.randint(0, 255):02X}" for _ in range(length)])

def create_dashboard(throughput_secure, pdr_secure, retransmissions, ciphertext):
    """Builds the rich layout for the dashboard."""
    
    # 1. Header Layout
    header = Text("🔒 SECURE EMBEDDED COMMUNICATION DASHBOARD 🔒", style="bold magenta", justify="center")
    
    # 2. Node Info Panels
    node_a_text = Text.assemble(
        ("Node State:\t", "cyan"), ("TRANSMITTING\n", "bold green"),
        ("Encryption:\t", "cyan"), ("AES-256-GCM ACTIVE\n", "bold green"),
        ("Current Sequence:\t", "cyan"), (f"{random.randint(1000, 9999)}", "bold yellow")
    )
    panel_a = Panel(node_a_text, title="[bold magenta]NODE A (SENDER)[/]", border_style="magenta", box=box.ROUNDED)

    node_b_text = Text.assemble(
        ("Node State:\t", "cyan"), ("LISTENING\n", "bold green"),
        ("MAC Verification:\t", "cyan"), ("✅ VALID\n", "bold green"),
        ("Replay Protection:\t", "cyan"), ("✅ SEQ ACCEPTED", "bold green")
    )
    panel_b = Panel(node_b_text, title="[bold magenta]NODE B (RECEIVER)[/]", border_style="magenta", box=box.ROUNDED)
    
    # Combine Nodes horizontally
    node_grid = Table.grid(expand=True)
    node_grid.add_column(ratio=1)
    node_grid.add_column(ratio=1)
    node_grid.add_row(panel_a, panel_b)

    # 3. Performance Metrics Table
    metrics_table = Table(
        title="[bold cyan]LIVE COMMUNICATION PERFORMANCE PROFILING (OPTION 2)[/]",
        box=box.SIMPLE_HEAVY,
        expand=True,
        header_style="bold magenta",
        border_style="magenta"
    )
    
    metrics_table.add_column("Performance Metric", style="cyan", justify="left")
    metrics_table.add_column("Insecure Baseline", style="blue", justify="center")
    metrics_table.add_column("Secure Hardened (Active)", style="bold white", justify="center")

    # Add Rows (simulating the data from the video)
    metrics_table.add_row(
        "Connection Establishment Time", 
        "8.5 ms", 
        "12.4 ms"
    )
    metrics_table.add_row(
        "End-to-End Latency", 
        "0.0143 ms", 
        f"0.04{random.randint(10, 99)} ms"
    )
    metrics_table.add_row(
        "Throughput", 
        "70,000 FPS", 
        f"{throughput_secure:,.3f} FPS"
    )
    metrics_table.add_row(
        "Packet Delivery Ratio (PDR)", 
        "100.00%", 
        f"{pdr_secure:.2f}%"
    )
    metrics_table.add_row(
        "Retransmission Count", 
        "0", 
        f"{retransmissions}"
    )
    metrics_table.add_row(
        "Protocol Overhead", 
        "0%", 
        "[bold red]+186%[/]"
    )

    metrics_panel = Panel(metrics_table, border_style="magenta")

    # 4. Footer (Live Ciphertext)
    footer_text = Text(f"Live Ciphertext Intercept: {ciphertext}...", style="dim white")
    
    # 5. Assemble Main Layout
    layout = Layout()
    layout.split(
        Layout(header, size=3),
        Layout(node_grid, size=7),
        Layout(metrics_panel),
        Layout(footer_text, size=3)
    )
    
    return layout

def main():
    # Initial Simulation Values
    throughput_secure = 24100.0
    retransmissions = 0
    pdr_secure = 100.00
    
    # Start the Live dashboard
    with Live(create_dashboard(throughput_secure, pdr_secure, retransmissions, generate_hex_string()), refresh_per_second=10) as live:
        try:
            while True:
                # Simulate live fluctuating data similar to the video
                throughput_secure = 24000.0 + random.uniform(-100, 900)
                
                # Occasionally drop PDR slightly and increase retransmissions
                if random.random() > 0.8:
                    pdr_secure = random.uniform(99.90, 99.99)
                    retransmissions += random.randint(0, 2)
                else:
                    pdr_secure = 100.00
                
                ciphertext = generate_hex_string()
                
                # Update the dashboard layout with new values
                live.update(create_dashboard(throughput_secure, pdr_secure, retransmissions, ciphertext))
                time.sleep(0.1) # 100ms update rate
                
        except KeyboardInterrupt:
            pass # Stop gracefully on Ctrl+C

if __name__ == "__main__":
    main()
