#!/usr/bin/env python3

from rich.console import Console
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.align import Align

console = Console()

def generate_dashboard():
    # Set up the main layout grid
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="profiling", size=11),
        Layout(name="security", size=13),
        Layout(name="verdict", size=8)
    )
    
    # 1. HEADER
    layout["header"].update(Panel(Align.center("[bold cyan]🚀 SECURE EMBEDDED COMMUNICATION DASHBOARD 🚀[/bold cyan]"), style="bold blue"))
    
    # 2. PERFORMANCE PROFILING TABLE
    profiling_table = Table(expand=True, show_lines=True)
    profiling_table.add_column("Performance Metric", style="bold yellow", justify="left")
    profiling_table.add_column("Insecure Baseline (Before)", justify="center", style="dim")
    profiling_table.add_column("Secure Hardened (After)", justify="center", style="bold white")
    
    # Metrics extracted from benchmark sources
    profiling_table.add_row("Connection Establishment Time", "0.5 ms", "12.4 ms")
    profiling_table.add_row("End-to-End Latency", "0.0143 ms", "0.0409 ms")
    profiling_table.add_row("Throughput (Packets/sec)", "70,006.88 PPS", "24,444.28 PPS")
    profiling_table.add_row("Maximum Jitter", "0.8059 ms", "2.0025 ms")
    profiling_table.add_row("Protocol Overhead", "0%", "[red]+186%[/red]")
    
    layout["profiling"].update(Panel(profiling_table, title="[bold magenta]📊 COMMUNICATION PERFORMANCE PROFILING (DOMAIN 4)[/bold magenta]", border_style="magenta"))
    
    # 3. THREAT MITIGATION MATRIX
    security_table = Table(expand=True, show_lines=True)
    security_table.add_column("Attack Vector", style="bold cyan")
    security_table.add_column("Baseline (Before)", style="red")
    security_table.add_column("Secure (After)", style="green")
    security_table.add_column("Mitigation Mechanism", style="yellow")

    # Attack data extracted from the automated evaluation framework
    security_table.add_row("Sniffing", "❌ Cleartext Exposed", "✅ Data Obfuscated", "AES-256-GCM Encryption")
    security_table.add_row("Tamper", "❌ Payload Altered", "✅ Blocked (Detected)", "GCM Authentication Tag")
    security_table.add_row("Replay", "❌ Processed Twice", "✅ Blocked (Detected)", "Sequence & Timestamp Tracking")
    security_table.add_row("Inject", "❌ Accepted as Valid", "✅ Blocked (Auth Failed)", "GCM Authentication Tag")
    security_table.add_row("Drop / Delay", "❌ Unhandled Loss", "✅ Handled Safely", "Timeout / Timestamp Expiration")

    layout["security"].update(Panel(security_table, title="[bold red]🚨 THREAT MITIGATION MATRIX[/bold red]", border_style="red"))

    # 4. FINAL VERDICT & SCORING
    verdict_table = Table(show_header=False, expand=True, box=None)
    verdict_table.add_row(
        "[bold dim]INSECURE BASELINE[/bold dim]\n[bold red]Score: 10 / 100 (Grade: F - CRITICAL RISK)[/bold red]\nConfidentiality: 0/25 | Integrity: 0/25\nReplay Resistance: 0/25 | Resilience: 10/25",
        "[bold white]SECURE FRAMEWORK[/bold white]\n[bold green]Score: 98 / 100 (Grade: A+ - ENTERPRISE GRADE)[/bold green]\nConfidentiality: 25/25 | Integrity: 25/25\nReplay Resistance: 25/25 | Resilience: 23/25"
    )
    
    layout["verdict"].update(Panel(verdict_table, title="[bold yellow]🏆 PROTOCOL SECURITY SCORING[/bold yellow]", border_style="yellow"))

    return layout

if __name__ == "__main__":
    console.print(generate_dashboard())
