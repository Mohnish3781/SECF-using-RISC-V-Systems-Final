#!/usr/bin/env python3
import os
import time

import packet_utils as pu
import crypto_utils as cu
import sequence_manager as sm

PIPE_OUT = "/tmp/nodeA_to_attacker"
SHARED_PASSWORD = "StrongSharedPassword123"  # Pre-Shared Key (PSK)

def main():
    print("[*] Secure Sender Node (Node A) Online.")
    print(f"[*] Target Pipe: {PIPE_OUT}")
    
    sm.initialize_sequence()
    
    message = b"HELLO FROM SECURE NODE A"
    
    pkt = pu.Packet()
    pkt.src_id = 1
    pkt.dest_id = 2
    pkt.type = 1
    pkt.seq = sm.get_next_sequence()
    pkt.timestamp = int(time.time())
    pkt.length = len(message)
    
    print(f"[+] Generating Packet -> Sequence: {pkt.seq}, Timestamp: {pkt.timestamp}")

    # This prevents the orchestrator from altering the source, dest, or sequence numbers.
    aad = pu.get_authenticated_header(pkt)
    
    print("[+] Encrypting payload and generating GCM Authentication Tag...")
    salt, nonce, ciphertext, tag = cu.encrypt_payload(
        payload=message,
        password=SHARED_PASSWORD,
        aad=aad
    )
    
    pkt.salt = salt
    pkt.nonce = nonce
    pkt.tag = tag
    pkt.payload = ciphertext
    
    binary_frame = pu.serialize_packet(pkt)
    
    print("[*] Opening channel and transmitting encrypted frame...")
    try:
        fd = os.open(PIPE_OUT, os.O_WRONLY)
        os.write(fd, binary_frame)
        os.close(fd)
        print("[SUCCESS] Secure frame dispatched.")
    except Exception as e:
        print(f"[-] Transmission failed: {e}")

if __name__ == "__main__":
    main()
