#!/usr/bin/env python3
"""
Hardware MITM Attack Dashboard
Interfaces with the serial MITM orchestrator to trigger physical attacks.
"""
import serial
import time
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

CONSOLE = Console()
# Sending control signals to the Python MITM Orchestrator via an internal socket or config file
# For hardware, we simulate sending a trigger to the orchestrator logic
ORCHESTRATOR_CONTROL_PORT = "/tmp/mitm_control" 

def display_menu():
    CONSOLE.print(Panel("[bold red]Hardware MITM Attack Simulation Engine[/bold red]\n"
                        "Target: ESP32 UART Physical Link (Node A -> Node B)", style="red"))
    CONSOLE.print("1. [cyan]Sniff Traffic[/cyan] (Passive Monitor)")
    CONSOLE.print("2. [yellow]Tamper Payload[/yellow] (Bit-flip Ciphertext)")
    CONSOLE.print("3. [magenta]Replay Attack[/magenta] (Capture & Resend)")
    CONSOLE.print("4. [red]Inject Forgery[/red] (Arbitrary Frame Creation)")
    CONSOLE.print("5. [white]Exit[/white]")

def run_dashboard():
    while True:
        display_menu()
        choice = Prompt.ask("Select Attack Vector", choices=["1", "2", "3", "4", "5"])
        
        if choice == "5":
            CONSOLE.print("[*] Exiting Attack Engine.")
            break
            
        mode_map = {"1": "sniff", "2": "tamper", "3": "replay", "4": "inject"}
        selected_mode = mode_map[choice]
        
        CONSOLE.print(f"\n[!] Instructing hardware proxy to execute: [bold]{selected_mode.upper()}[/bold]")
        CONSOLE.print("[*] Please run `python3 Secure_mitm_orchestrator_2.py --mode " + selected_mode + "` in your proxy terminal.\n")
        time.sleep(2)

if __name__ == "__main__":
    run_dashboard()
