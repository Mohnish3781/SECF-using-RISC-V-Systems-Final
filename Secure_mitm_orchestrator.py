import serial
import struct
import time
import argparse
import binascii

# Hardware COM ports replace named pipes
SERIAL_PORT_IN = "/dev/ttyUSB0"  # Node A
SERIAL_PORT_OUT = "/dev/ttyUSB1" # Node B
BAUD_RATE = 115200

PACKET_FORMAT = "<IBBBHII12s16s16s256s"
PACKET_SIZE = struct.calcsize(PACKET_FORMAT) # 317 bytes

class SecureMitmOrchestrator:
    def __init__(self, mode, inject_msg=None):
        self.mode = mode
        self.inject_msg = inject_msg
        self.replay_cache = []

    def compute_crc32(self, data_bytes):
        return binascii.crc32(data_bytes) & 0xFFFFFFFF

    def run(self):
        print(f"[*] Initializing Active Intercept Layer via PySerial. Mode: [{self.mode.upper()}]")
        
        # Connect to physical ESP32 nodes
        ser_in = serial.Serial(SERIAL_PORT_IN, BAUD_RATE, timeout=1)
        ser_out = serial.Serial(SERIAL_PORT_OUT, BAUD_RATE, timeout=1)
        print("[+] Hardware UART proxy routing engaged.\n")

        while True:
            try:
                # Read exactly 317 bytes from serial stream
                raw_packet = ser_in.read(PACKET_SIZE)
                
                if len(raw_packet) < PACKET_SIZE:
                    continue

                (magic, ptype, src_id, dest_id, length, seq, timestamp,
                 nonce, salt, tag, payload) = struct.unpack(PACKET_FORMAT, raw_packet)

                print("\033[94m" + "=" * 60)
                print(f"[INTERCEPTED FRAME] Sequence Index: {seq}")
                print(f"  ├── AES Nonce (12B)  : {nonce.hex()}")
                print("=" * 60 + "\033[0m")

                # Forward modified or unmodified packet to Node B
                ser_out.write(raw_packet)

            except KeyboardInterrupt:
                print("\n[*] Intercept routine terminated.")
                break

        ser_in.close()
        ser_out.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["sniff", "tamper", "replay", "inject"], required=True)
    args = parser.parse_args()
    engine = SecureMitmOrchestrator(mode=args.mode)
    engine.run()
