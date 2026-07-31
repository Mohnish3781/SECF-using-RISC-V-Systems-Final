#!/usr/bin/env python3
"""
IITI SOC 2026 - PS8 Final Evaluation
SECURE MITM ORCHESTRATOR - Attacks the HARDENED protocol
Mirrors mitm_orchestrator.py (baseline) but targets the AES-256-GCM +
HMAC-SHA256 + sequence-counter protocol from hardened_sender/receiver.

PURPOSE: Demonstrate that the four attacks which succeeded against the
baseline (sniff, tamper, replay, inject) now FAIL against the hardened
protocol. This script does the interception/tampering/replay/forgery;
the *failure* is visible in the hardened_receiver's own output
(HMAC verification failed / GCM tag failed / replay detected), because
this script does NOT have session_key or hmac_key — exactly like a
real network attacker.

PIPE TOPOLOGY FOR THIS DEMO (different from direct sender<->receiver
testing):
    hardened_sender  --> /tmp/secure_nodeA_to_attacker --> [this script] --> /tmp/secure_attacker_to_nodeB --> hardened_receiver

Before running this demo, point the receiver at the relay's output pipe
instead of listening directly on the sender's pipe:
  in hardened_receiver_complete.c, set:
    const char *pipe_from_attacker = "/tmp/secure_attacker_to_nodeB";
  (recompile). For direct sender<->receiver testing with no MITM in the
  loop, keep it as "/tmp/secure_nodeA_to_attacker" instead.

USAGE (matches the baseline script's CLI):
  python3 secure_mitm_orchestrator.py --mode sniff
  python3 secure_mitm_orchestrator.py --mode tamper
  python3 secure_mitm_orchestrator.py --mode replay
  python3 secure_mitm_orchestrator.py --mode inject --message "FORGED COMMAND"
"""

import os
import sys
import struct
import time
import argparse

PIPE_IN = "/tmp/secure_nodeA_to_attacker"
PIPE_OUT = "/tmp/secure_attacker_to_nodeB"

# --- HARDENED PACKET FORMAT (must match the packed C struct exactly) ---
# header(4) type(1) src(1) dest(1) length(2) seq(4) timestamp(4)
# nonce(12) salt(16, carries HMAC) tag(16, GCM auth tag) payload(256)
PACKET_FORMAT = "<IBBBHII12s16s16s256s"
PACKET_SIZE = struct.calcsize(PACKET_FORMAT)  # 317 bytes


class SecureMitmOrchestrator:
    def __init__(self, mode, inject_msg=None):
        self.mode = mode
        self.inject_msg = inject_msg
        self.replay_cache = []

    def run(self):
        if self.mode == "inject":
            self.execute_standalone_injection()
            return

        print(f"[*] Initializing Active Intercept Layer vs HARDENED protocol. Strategy: [{self.mode.upper()}]")
        print(f"[*] Packet size expected: {PACKET_SIZE} bytes\n")

        if not os.path.exists(PIPE_IN):
            print(f"[-] Missing pipe: {PIPE_IN} (start hardened_sender's mkfifo first, or run the sender once)")
            sys.exit(1)

        fd_in = os.open(PIPE_IN, os.O_RDONLY)
        if not os.path.exists(PIPE_OUT):
            os.mkfifo(PIPE_OUT)
        fd_out = os.open(PIPE_OUT, os.O_WRONLY)
        print("[+] Proxy routing channels engaged.\n")

        while True:
            try:
                raw_packet = os.read(fd_in, PACKET_SIZE)
                if not raw_packet:
                    print("[*] Stream terminated by sender.")
                    break
                if len(raw_packet) < PACKET_SIZE:
                    print(f"[-] Incomplete frame ({len(raw_packet)}/{PACKET_SIZE}). Skipping.")
                    continue

                (magic, ptype, src_id, dest_id, length, seq, timestamp,
                 nonce, salt, tag, payload) = struct.unpack(PACKET_FORMAT, raw_packet)

                print("\033[94m" + "=" * 60)
                print(f"[INTERCEPTED FRAME] Sequence: {seq}")
                print(f"  ├── Magic     : {hex(magic).upper()}")
                print(f"  ├── Src->Dst  : {src_id} -> {dest_id}")
                print(f"  ├── Nonce     : {nonce.hex()}")
                print(f"  ├── HMAC(salt): {salt.hex()}")
                print(f"  ├── GCM Tag   : {tag.hex()}")
                # This is the whole point: without session_key, this is NOT
                # the plaintext. Compare to the baseline demo where this
                # line printed a readable string.
                print(f"  └── \"Payload\" bytes (ciphertext, unreadable): {payload[:length].hex()[:48]}...")
                print("=" * 60 + "\033[0m")

                if self.mode == "sniff":
                    try:
                        decoded_attempt = payload[:length].decode("utf-8")
                        print(f"[!] Unexpected: payload decoded as text: {decoded_attempt}")
                    except UnicodeDecodeError:
                        print("[+] Confirmed: intercepted bytes are NOT valid UTF-8 text.")
                        print("    Confidentiality holds — AES-256-GCM ciphertext, no key available to this script.\n")

                if self.mode == "replay":
                    self.replay_cache.append(raw_packet)
                    print("[+] Replay subsystem: cached this valid encrypted frame.\n")

                if self.mode == "tamper":
                    # Flip a byte in the ciphertext payload, like the baseline
                    # attack, but WITHOUT being able to recompute a valid GCM
                    # tag or HMAC (we don't have the keys). This should make
                    # the receiver reject the frame.
                    mutated_payload = bytearray(payload)
                    if length > 0:
                        mutated_payload[0] ^= 0xFF
                    print("[!] Flipping one ciphertext byte (no way to fix tag/HMAC without the keys)...\n")
                    raw_packet = struct.pack(PACKET_FORMAT, magic, ptype, src_id, dest_id,
                                              length, seq, timestamp, nonce, salt, tag,
                                              bytes(mutated_payload))

                os.write(fd_out, raw_packet)

                if self.mode == "replay" and self.replay_cache:
                    time.sleep(2)
                    print("\033[33m[!] REPLAY ATTACK: Re-injecting a previously-seen encrypted frame...\033[0m")
                    try:
                        os.write(fd_out, self.replay_cache[0])
                        print("    Sent duplicate frame — watch the receiver reject it as a replay.\n")
                    except BrokenPipeError:
                        print("    [FAILURE] Broken pipe — receiver not running.\n")
                    self.replay_cache.clear()

            except KeyboardInterrupt:
                print("\n[*] Intercept routine terminated.")
                break
            except Exception as e:
                print(f"[-] Runtime error: {e}")
                break

        os.close(fd_in)
        os.close(fd_out)

    def execute_standalone_injection(self):
        """ATTACK CLASS 4: forged packet injection — no sender involved at all."""
        print("[*] Forged Packet Injection vs HARDENED protocol...")
        print("[*] Attacker does not know session_key or hmac_key.\n")

        if not os.path.exists(PIPE_OUT):
            os.mkfifo(PIPE_OUT)
        fd_out = os.open(PIPE_OUT, os.O_WRONLY)

        fake_msg = self.inject_msg.encode("utf-8", errors="ignore")
        fake_len = len(fake_msg)
        fake_payload = fake_msg.ljust(256, b"\x00")   # NOT real ciphertext — attacker has no key
        fake_nonce = os.urandom(12)
        fake_salt = os.urandom(16)                     # attacker can't compute the real HMAC
        fake_tag = os.urandom(16)                       # attacker can't compute the real GCM tag

        packet = struct.pack(PACKET_FORMAT, 0xABCD1234, 1, 1, 2, fake_len, 1337, 0,
                              fake_nonce, fake_salt, fake_tag, fake_payload)

        print("\033[95m" + "!" * 60)
        print(f"[PACKET FORGERY DISPATCHED] \"{self.inject_msg}\"")
        print(f"  Magic header matches, but tag/HMAC are guesses — no key access.")
        print("!" * 60 + "\033[0m\n")

        os.write(fd_out, packet)
        os.close(fd_out)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IITI SOC 2026 Track 3 - Secure Protocol Attack Verification")
    parser.add_argument("--mode", choices=["sniff", "tamper", "replay", "inject"], required=True)
    parser.add_argument("--message", type=str, default="FORGED COMMAND FROM ATTACKER",
                         help="Payload for standalone injection attempts.")
    args = parser.parse_args()
    engine = SecureMitmOrchestrator(mode=args.mode, inject_msg=args.message)
    engine.run()
