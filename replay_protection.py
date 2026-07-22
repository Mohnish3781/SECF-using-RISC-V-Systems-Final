# replay_protection.py

import os
import struct

# =====================================================
# Configuration
# =====================================================

REPLAY_FILE = "receiver_state.bin"

INITIAL_SEQUENCE = 0


# =====================================================
# Initialize Receiver State
# =====================================================

def initialize_replay():

    if not os.path.exists(REPLAY_FILE):

        with open(REPLAY_FILE, "wb") as file:

            file.write(struct.pack("!I", INITIAL_SEQUENCE))


# =====================================================
# Read Highest Sequence Number
# =====================================================

def get_last_sequence():

    initialize_replay()

    with open(REPLAY_FILE, "rb") as file:

        data = file.read(4)

        if len(data) != 4:

            return INITIAL_SEQUENCE

        sequence = struct.unpack("!I", data)[0]

    return sequence


# =====================================================
# Save Highest Sequence Number
# =====================================================

def update_last_sequence(sequence):

    with open(REPLAY_FILE, "wb") as file:

        file.write(struct.pack("!I", sequence))


# =====================================================
# Replay Detection
# =====================================================

def is_replay(sequence):

    """
    Returns True if packet is replayed.
    """

    last_sequence = get_last_sequence()

    if sequence <= last_sequence:

        return True

    update_last_sequence(sequence)

    return False


# =====================================================
# Reset Replay Protection
# =====================================================

def reset_replay():

    with open(REPLAY_FILE, "wb") as file:

        file.write(struct.pack("!I", INITIAL_SEQUENCE))


# =====================================================
# Print Receiver State
# =====================================================

def print_state():

    print("--------------------------------")

    print("Highest Sequence Received :", get_last_sequence())

    print("--------------------------------")


# =====================================================
# Test
# =====================================================

if __name__ == "__main__":

    reset_replay()

    packets = [1, 2, 3, 3, 4, 2, 5]

    for packet in packets:

        if is_replay(packet):

            print(packet, "Replay Attack Detected")

        else:

            print(packet, "Packet Accepted")