import struct
import binascii

# Hardware struct mapping (Matches #pragma pack(1) in C)
# < (Little Endian), I (4B), B (1B), H (2B), s (char array)
HARDWARE_PACKET_FORMAT = "<IBBBHII12s16s16s256s"
PACKET_SIZE = struct.calcsize(HARDWARE_PACKET_FORMAT)

def parse_hardware_frame(raw_bytes):
    """Safely unwrap 317-byte ESP32 UART frames."""
    if len(raw_bytes) != PACKET_SIZE:
        raise ValueError(f"Frame size mismatch: Expected {PACKET_SIZE}, got {len(raw_bytes)}")
        
    return struct.unpack(HARDWARE_PACKET_FORMAT, raw_bytes)

def calculate_telemetry_crc(raw_bytes):
    """Calculates CRC32 for telemetry tracking without modifying the frame."""
    return binascii.crc32(raw_bytes) & 0xFFFFFFFF
