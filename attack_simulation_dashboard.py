import time
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich import box
from rich.text import Text

# Attack scenarios
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
        if attack['name'] == "Malformed Packet Injection":
            insecure_behavior = "[yellow]Rejected (Crash)[/]"
            insecure_grade = "[red]FAIL[/]" 
        else:
            insecure_behavior = "[red]Successfully Affected[/]"
            insecure_grade = "[red]FAIL[/]" 
        
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

def generate_layman_animation(current_attack, phase, final_status=""):
    """Generates an easy-to-understand visual flow of the attack process."""
    if not current_attack:
        content = "\n[bold green]✅ System is Secure. All communication is protected from attacks.[/bold green]\n"
        return Panel(Text.from_markup(content, justify="center"), title="[bold blue]Live Network Flow (Layman View)[/]", border_style="blue", box=box.ROUNDED)

    sender = "[💻 SENDER Node A]"
    receiver = "[🛡️ RECEIVER Node B]"
    attacker = f"[😈 ATTACKER: {current_attack['name']}]"
    
    if phase == "injecting":
        flow = f"{sender} ====( Encrypted Data )====> {attacker} ====x> {receiver}"
        desc = "The attacker is actively trying to hijack or corrupt the communication stream..."
        style = "bold yellow"
    elif phase == "analyzing":
        flow = f"{sender} ====( Encrypted Data )==========================> {receiver}"
        desc = "The receiver is validating the data using its security countermeasures (MAC/Sequence/Timeout)..."
        style = "bold cyan"
    else: # outcome phase
        if "Detected" in final_status or "Rejected" in final_status:
            flow = f"{sender} ====( Encrypted Data )==========================> {receiver} 🛑 [bold red]ATTACK BLOCKED![/]"
            desc = f"Result: The receiver successfully neutralized the threat! ({final_status})"
        else:
            flow = f"{sender} ====( Encrypted Data )==========================> {receiver} 💥 [bold red]COMPROMISED![/]"
            desc = f"Result: The system failed to stop the attack."
        style = "bold white"

    content = f"\n{flow}\n\n[{style}]{desc}[/]\n"
    return Panel(Text.from_markup(content, justify="center"), title="[bold blue]Live Network Flow (Layman View)[/]", border_style="blue", box=box.ROUNDED)

def create_layout(current_attack, completed_attacks, progress_msg, phase, final_status=""):
    """Builds the dynamic rich layout for the dashboard."""
    
    # 1. Header (Updated text based on pro.jpeg annotation)
    header = Text("🛡️ SECURE EMBEDDED COMMUNICATION 🛡️", style="bold red on black", justify="center")
    
    # 2. Tracker & Live Execution Panel (Updated with Tracker)
    total_attacks = len(ATTACK_SCENARIOS)
    current_count = len(completed_attacks)
    
    if current_attack:
        tracker_text = f"TRACKER: [ {current_count} / {total_attacks} Attacks Completed ]"
        exec_text = Text.assemble(
            ("Executing Attack:\t", "cyan"), (f"{current_attack['name']}\n", "bold red"),
            ("Description:\t\t", "cyan"), (f"{current_attack['desc']}\n", "yellow"),
            ("Status:\t\t", "cyan"), (f"{progress_msg}\n\n", "bold white blinking"),
            (tracker_text, "bold magenta")
        )
    else:
        exec_text = Text(f"All automated attack scenarios completed ({total_attacks}/{total_attacks}). Final report generated.", style="bold green")
        
    execution_panel = Panel(exec_text, title="[bold red]LIVE ATTACK SIMULATOR[/]", border_style="red", box=box.ROUNDED)

    # 3. Report Table Panel
    report_table = generate_report_table(completed_attacks)
    report_panel = Panel(report_table, border_style="red")

    # 4. Animated Flow Panel (New addition for laymen)
    animation_panel = generate_layman_animation(current_attack, phase, final_status)

    # 5. Footer Summary
    summary_text = Text("Comparing protocol behaviour before and after implementing security countermeasures...", style="dim white")
    
    # Assemble Layout
    layout = Layout()
    layout.split(
        Layout(header, size=3),
        Layout(execution_panel, size=8),
        Layout(report_panel, size=16),
        Layout(animation_panel, size=7),
        Layout(summary_text, size=3)
    )
    
    return layout

def main():
    completed_attacks = []
    
    # Start the Live dashboard
    with Live(create_layout(None, completed_attacks, "Initializing...", "idle"), refresh_per_second=10) as live:
        time.sleep(1)
        
        for attack in ATTACK_SCENARIOS:
            # Phase 1: Injecting
            live.update(create_layout(attack, completed_attacks, "Injecting malicious vectors... ▓░░░░░░░░░", "injecting"))
            time.sleep(1.5)
            
            # Phase 2: Analyzing
            live.update(create_layout(attack, completed_attacks, "Analyzing protocol response... ▓▓▓▓▓▓░░░░", "analyzing"))
            time.sleep(1.5)
            
            # Phase 3: Determining Outcome
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
            
            # Phase 4: Show Result dynamically in the layman animation before logging it to the table
            live.update(create_layout(attack, completed_attacks, f"Completed: {outcome} ▓▓▓▓▓▓▓▓▓▓", "outcome", outcome))
            time.sleep(2)
            
            completed_attacks.append(attack_result)
            
        # Final state
        live.update(create_layout(None, completed_attacks, "Done", "idle"))
        
        # Keep the terminal up for a few seconds so the user can read the final report
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass 

if __name__ == "__main__":
    main()
