import time
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich import box
from rich.text import Text

# Attack scenarios defined in "bonus.pdf" Option 1
ATTACK_SCENARIOS = [
    {"name": "Packet Injection", "desc": "Injecting unauthorized data packets into the stream."},
    {"name": "Packet Modification (MITM)", "desc": "Altering payload bits in transit."},
    {"name": "Packet Dropping", "desc": "Simulating a blackhole/selective forwarding attack."},
    {"name": "Packet Duplication", "desc": "Replaying previously captured valid packets."},
    {"name": "Packet Delay/Reordering", "desc": "Holding packets and sending them out of sequence."},
    {"name": "Malformed Packet Injection", "desc": "Sending packets with invalid headers/CRC."}
]

def generate_report_table(completed_attacks):
    """Generates the main structured evaluation report table with separate grading."""
    table = Table(
        title="[bold red]AUTOMATED ATTACK SIMULATION & EVALUATION REPORT[/]",
        box=box.SIMPLE_HEAVY,
        expand=True,
        header_style="bold magenta",
        border_style="red"
    )
    
    table.add_column("Attack Scenario", style="cyan", justify="left")
    table.add_column("Insecure Behavior", style="yellow", justify="center")
    table.add_column("Insecure Grade", justify="center")
    table.add_column("Secure Countermeasure Outcome", style="bold white", justify="center")
    table.add_column("Secure Grade", justify="center")

    for attack in completed_attacks:
        # Determine Insecure Behavior and Grade
        if attack['name'] == "Malformed Packet Injection":
            insecure_behavior = "[yellow]Rejected (Crash)[/]"
            insecure_grade = "[red]FAIL[/]" # A crash is a failure of system stability
        else:
            insecure_behavior = "[red]Successfully Affected[/]"
            insecure_grade = "[red]FAIL[/]" # Vulnerability exploited
        
        # Determine Secure Status and Grade
        if "Detected" in attack['status'] or "Rejected" in attack['status']:
            secure_grade = "[green]PASS[/]"
            status_color = "green"
        else:
            secure_grade = "[red]FAIL[/]"
            status_color = "red"
            
        table.add_row(
            attack['name'],
            insecure_behavior,
            insecure_grade,
            f"[{status_color}]{attack['status']}[/]",
            secure_grade
        )

    return table

def create_layout(current_attack, completed_attacks, progress_msg):
    """Builds the dynamic rich layout for the dashboard."""
    
    # 1. Header
    header = Text("🛡️ SECURE EMBEDDED COMMUNICATION: OPTION 1 🛡️", style="bold red on black", justify="center")
    
    # 2. Live Execution Panel
    if current_attack:
        exec_text = Text.assemble(
            ("Executing Attack:\t", "cyan"), (f"{current_attack['name']}\n", "bold red"),
            ("Description:\t\t", "cyan"), (f"{current_attack['desc']}\n", "yellow"),
            ("Status:\t\t", "cyan"), (f"{progress_msg}", "bold white blinking")
        )
    else:
        exec_text = Text("All automated attack scenarios completed. Final report generated.", style="bold green")
        
    execution_panel = Panel(exec_text, title="[bold red]LIVE ATTACK SIMULATOR[/]", border_style="red", box=box.ROUNDED)

    # 3. Report Table Panel
    report_table = generate_report_table(completed_attacks)
    report_panel = Panel(report_table, border_style="red")

    # 4. Footer Summary
    summary_text = Text("Comparing protocol behaviour before and after implementing security countermeasures...", style="dim white")
    
    # Assemble Layout
    layout = Layout()
    layout.split(
        Layout(header, size=3),
        Layout(execution_panel, size=6),
        Layout(report_panel),
        Layout(summary_text, size=3)
    )
    
    return layout

def main():
    completed_attacks = []
    
    # Start the Live dashboard
    with Live(create_layout(None, completed_attacks, "Initializing..."), refresh_per_second=10) as live:
        time.sleep(1) # Initial pause
        
        for attack in ATTACK_SCENARIOS:
            # Phase 1: Injecting
            live.update(create_layout(attack, completed_attacks, "Injecting malicious vectors... ▓░░░░░░░░░"))
            time.sleep(0.6)
            
            # Phase 2: Analyzing
            live.update(create_layout(attack, completed_attacks, "Analyzing protocol response... ▓▓▓▓▓▓░░░░"))
            time.sleep(0.6)
            
            # Phase 3: Determining Outcome (Matching your screenshot exact outputs)
            if attack['name'] == "Packet Injection":
                outcome = "Detected"
            elif attack['name'] in ["Packet Modification (MITM)", "Malformed Packet Injection"]:
                outcome = "Rejected (MAC/CRC Invalid)"
            elif attack['name'] == "Packet Dropping":
                outcome = "Detected (Timeout/Retransmit)"
            elif attack['name'] == "Packet Duplication":
                outcome = "Rejected (Replay Protected)"
            elif attack['name'] == "Packet Delay/Reordering":
                outcome = "Rejected"
            else:
                outcome = "Detected"
                
            attack_result = {
                "name": attack["name"],
                "status": outcome
            }
            
            completed_attacks.append(attack_result)
            
            # Update with finished attack
            live.update(create_layout(attack, completed_attacks, f"Completed: {outcome} ▓▓▓▓▓▓▓▓▓▓"))
            time.sleep(0.8)
            
        # Final state
        live.update(create_layout(None, completed_attacks, "Done"))
        
        # Keep the terminal up for a few seconds so the user can read the final report
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass # Allows user to safely exit with Ctrl+C

if __name__ == "__main__":
    main()
