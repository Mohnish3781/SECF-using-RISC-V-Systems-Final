#!/usr/bin/env python3
import os

import packet_utils as pu
import crypto_utils as cu
import replay_protection as rp

PIPE_IN = "/tmp/attacker_to_nodeB"
SHARED_PASSWORD = "StrongSharedPassword123"  # Pre-Shared Key (PSK)

def main():
    print("[*] Secure Receiver Node (Node B) Online.")
    print(f"[*] Listening continuously on {PIPE_IN}...")
    
    rp.initialize_replay()

    while True:
        try:
            fd = os.open(PIPE_IN, os.O_RDONLY)
            
            while True:
                raw_data = os.read(fd, pu.PACKET_SIZE)
                
                if not raw_data:
                    break 
                
                if len(raw_data) < pu.PACKET_SIZE:
                    continue  # Ignore fragmented bytes
                
                print("\n" + "="*50)
                print("[*] Encrypted Frame Received. Processing...")
                
                try:
                    pkt = pu.deserialize_packet(raw_data)
                except ValueError as e:
                    print(f"[-] Dropping frame: {e}")
                    continue
                
                if pkt.header != pu.MAGIC_HEADER:
                    print(f"[-] Dropping frame: Invalid Magic Header (0x{pkt.header:X})")
                    continue
                
                if rp.is_replay(pkt.seq):
                    print(f"\033[91m[!] THREAT DETECTED: Replay Attack (Sequence {pkt.seq}). Frame dropped.\033[0m")
                    continue
                
                aad = pu.get_authenticated_header(pkt)
                
                try:
                    plaintext = cu.decrypt_payload(
                        ciphertext=pkt.payload,
                        password=SHARED_PASSWORD,
                        salt=pkt.salt,
                        nonce=pkt.nonce,
                        tag=pkt.tag,
                        aad=aad
                    )
                    
                    print("\033[92m[+] Authentication Verified! Payload Decrypted Successfully.\033[0m")
                    print(f"  ├── Sequence    : {pkt.seq}")
                    print(f"  ├── Timestamp   : {pkt.timestamp}")
                    print(f"  ├── Source ID   : {pkt.src_id}")
                    print(f"  └── Message     : {plaintext.decode('utf-8', errors='ignore')}")
                    
                except ValueError:
                    print("\033[91m[!] THREAT DETECTED: Authentication Failed! Frame was forged or tampered.\033[0m")
            
            os.close(fd)
            
        except KeyboardInterrupt:
            print("\n[*] Receiver gracefully shutting down.")
            break
        except Exception as e:
            print(f"[-] Runtime error: {e}")
            break

if __name__ == "__main__":
    main()
