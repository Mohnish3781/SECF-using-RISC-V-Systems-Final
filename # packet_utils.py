# packet_utils.py

import struct
from dataclasses import dataclass

# =====================================================
# Constants (Must match packet.h)
# =====================================================

MAGIC_HEADER = 0xABCD1234

MAX_PAYLOAD = 256
NONCE_SIZE = 12
SALT_SIZE = 16
TAG_SIZE = 16

# =====================================================
# Packet Layout
#
# uint32 header
# uint8  type
# uint8  src_id
# uint8  dest_id
# uint16 length
# uint32 seq
# uint32 timestamp
# 12B nonce
# 16B salt
# 16B tag
# 256B payload
# =====================================================

PACKET_FORMAT = "!IBBBHII12s16s16s256s"

PACKET_SIZE = struct.calcsize(PACKET_FORMAT)


# =====================================================
# Packet Class
# =====================================================

@dataclass
class Packet:

    header: int = MAGIC_HEADER

    type: int = 1

    src_id: int = 0

    dest_id: int = 0

    length: int = 0

    seq: int = 0

    timestamp: int = 0

    nonce: bytes = bytes(NONCE_SIZE)

    salt: bytes = bytes(SALT_SIZE)

    tag: bytes = bytes(TAG_SIZE)

    payload: bytes = b''


# =====================================================
# Serialize Packet
# =====================================================

def serialize_packet(packet: Packet) -> bytes:

    payload = packet.payload.ljust(MAX_PAYLOAD, b'\x00')

    return struct.pack(

        PACKET_FORMAT,

        packet.header,

        packet.type,

        packet.src_id,

        packet.dest_id,

        packet.length,

        packet.seq,

        packet.timestamp,

        packet.nonce,

        packet.salt,

        packet.tag,

        payload

    )


# =====================================================
# Deserialize Packet
# =====================================================

def deserialize_packet(data: bytes) -> Packet:

    if len(data) != PACKET_SIZE:
        raise ValueError("Invalid Packet Size")

    fields = struct.unpack(PACKET_FORMAT, data)

    pkt = Packet()

    pkt.header = fields[0]

    pkt.type = fields[1]

    pkt.src_id = fields[2]

    pkt.dest_id = fields[3]

    pkt.length = fields[4]

    pkt.seq = fields[5]

    pkt.timestamp = fields[6]

    pkt.nonce = fields[7]

    pkt.salt = fields[8]

    pkt.tag = fields[9]

    pkt.payload = fields[10][:pkt.length]

    return pkt


# =====================================================
# Header used as AES-GCM AAD
# =====================================================

def get_authenticated_header(packet: Packet) -> bytes:
    """
    These fields are authenticated but NOT encrypted.
    """

    return struct.pack(
        "!IBBBHII",

        packet.header,

        packet.type,

        packet.src_id,

        packet.dest_id,

        packet.length,

        packet.seq,

        packet.timestamp
    )


# =====================================================
# Print Packet
# =====================================================

def print_packet(packet: Packet):

    print("\n========== Packet ==========")

    print(f"Header       : {hex(packet.header)}")

    print(f"Type         : {packet.type}")

    print(f"Source ID    : {packet.src_id}")

    print(f"Destination  : {packet.dest_id}")

    print(f"Length       : {packet.length}")

    print(f"Sequence No. : {packet.seq}")

    print(f"Timestamp    : {packet.timestamp}")

    print(f"Nonce        : {packet.nonce.hex()}")

    print(f"Salt         : {packet.salt.hex()}")

    print(f"Tag          : {packet.tag.hex()}")

    print(f"Payload      : {packet.payload}")

    print("============================\n")