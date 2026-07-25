#!/usr/bin/env python3

import subprocess
import time
import os

# The exact attack scenarios required by Bonus Option 1
ATTACKS = ['sniff', 'tamper', 'replay', 'drop', 'delay', 'inject', 'malformed']

# Define the Before (Insecure) and After (Secure) executable commands
TEST_PHASES = {
    "BEFORE_SECURITY": {
        "receiver": ["./receiver_node"], 
        "sender": ["./sender_node"]
    },
    "AFTER_SECURITY": {
        "receiver": ["python3", "secure_receiver.py"],
        "sender": ["python3", "secure_sender.py"]
    }
}

def reset_pipes():
    """Clears and recreates named pipes to prevent cross-contamination between tests."""
    os.system("rm -f /tmp/nodeA_to_attacker /tmp/attacker_to_nodeB sequence.bin receiver_state.bin")
    os.system("mkfifo /tmp/nodeA_to_attacker /tmp/attacker_to_nodeB")

def evaluate_output(output, attack):
    """Analyzes the receiver's stdout logs to determine if the attack was blocked."""
    output_upper = output.upper()
    if "THREAT DETECTED" in output_upper or "FAILED" in output_upper or "REJECTED" in output_upper:
        return "✅ BLOCKED (Detected)"
    elif attack == "drop" and output.strip() == "":
        return "✅ HANDLED (No Data)"
    elif "SUCCESSFULLY DECRYPTED" in output_upper or "CAPTURED DATA" in output_upper or "RECEIVED:" in output_upper:
        return "❌ EXPLOITED (Bypassed)"
    else:
        return "⚠️ UNKNOWN/CRASHED"

def run_evaluation():
    print("="*65)
    print("🚀 AUTOMATED ATTACK SIMULATION & EVALUATION FRAMEWORK")
    print("="*65)
    
    results = {attack: {"BEFORE_SECURITY": "", "AFTER_SECURITY": ""} for attack in ATTACKS}

    for phase_name, cmds in TEST_PHASES.items():
        print(f"\n\n{'='*40}")
        print(f"🔄 INITIATING PHASE: {phase_name.replace('_', ' ')}")
        print(f"{'='*40}")

        for attack in ATTACKS:
            print(f"\n[*] Executing Test: {attack.upper()} attack...")
            reset_pipes()
            
            # 1. Start Receiver
            try:
                receiver = subprocess.Popen(
                    cmds["receiver"], 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE, 
                    text=True
                )
            except FileNotFoundError:
                print(f"    └── [ERROR] Could not find {cmds['receiver'][0]}. Skipping...")
                results[attack][phase_name] = "FILE NOT FOUND"
                continue
            
            # 2. Start MITM Orchestrator
            orchestrator = subprocess.Popen(
                ["python3", "mitm_orchestrator.py", "--mode", attack],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            time.sleep(1) # Allow pipe binding
            
            # 3. Trigger Sender (skip if we are just injecting data out of thin air)
            if attack not in ['inject', 'malformed']:
                try:
                    sender = subprocess.Popen(
                        cmds["sender"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    sender.wait(timeout=5)
                except FileNotFoundError:
                    pass
            
            time.sleep(2) # Allow receiver time to process logic
            
            # 4. Teardown
            orchestrator.kill()
            receiver.kill()
            
            # 5. Analyze Results
            output, _ = receiver.communicate()
            status = evaluate_output(output, attack)
            
            results[attack][phase_name] = status
            print(f"    └── Result: {status}")

    # 6. Generate the Markdown Report
    print("\n\n" + "="*75)
    print("📊 CONSOLIDATED EVALUATION REPORT GENERATED")
    print("="*75)
    
    header = f"| {'Attack Vector':<15} | {'Before Security':<22} | {'After Security':<22} |"
    divider = f"|{'-'*17}|{'-'*24}|{'-'*24}|"
    
    print(header)
    print(divider)
    
    with open("security_report.md", "w") as f:
        f.write("# Protocol Security Evaluation Report\n\n")
        f.write("This report compares protocol behaviour before and after implementing AES-GCM and Sequence validation countermeasures.\n\n")
        f.write(header + "\n")
        f.write(divider + "\n")
        
        for attack in ATTACKS:
            row = f"| {attack.upper():<15} | {results[attack]['BEFORE_SECURITY']:<22} | {results[attack]['AFTER_SECURITY']:<22} |"
            print(row)
            f.write(row + "\n")
            
    print("-" * 75)
    print("[+] Report successfully saved to 'security_report.md'")

if __name__ == "__main__":
    run_evaluation()
