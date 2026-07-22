# sequence_manager.py

import os
import struct

# =====================================================
# Configuration
# =====================================================

SEQUENCE_FILE = "sequence.bin"

INITIAL_SEQUENCE = 1


# =====================================================
# Initialize Sequence File
# =====================================================

def initialize_sequence():
    """
    Creates the sequence file if it doesn't exist.
    """

    if not os.path.exists(SEQUENCE_FILE):

        with open(SEQUENCE_FILE, "wb") as file:

            file.write(struct.pack("!I", INITIAL_SEQUENCE))


# =====================================================
# Read Current Sequence Number
# =====================================================

def get_current_sequence():

    initialize_sequence()

    with open(SEQUENCE_FILE, "rb") as file:

        data = file.read(4)

        if len(data) != 4:

            return INITIAL_SEQUENCE

        sequence = struct.unpack("!I", data)[0]

    return sequence


# =====================================================
# Get Next Sequence Number
# =====================================================

def get_next_sequence():

    sequence = get_current_sequence()

    with open(SEQUENCE_FILE, "wb") as file:

        file.write(struct.pack("!I", sequence + 1))

    return sequence


# =====================================================
# Reset Sequence
# =====================================================

def reset_sequence():

    with open(SEQUENCE_FILE, "wb") as file:

        file.write(struct.pack("!I", INITIAL_SEQUENCE))


# =====================================================
# Peek Current Sequence
# =====================================================

def peek_sequence():

    return get_current_sequence()


# =====================================================
# Set Sequence
# =====================================================

def set_sequence(sequence):

    with open(SEQUENCE_FILE, "wb") as file:

        file.write(struct.pack("!I", sequence))


# =====================================================
# Print Sequence
# =====================================================

def print_sequence():

    print("--------------------------------")

    print("Current Sequence :", get_current_sequence())

    print("--------------------------------")


# =====================================================
# Test
# =====================================================

if __name__ == "__main__":

    initialize_sequence()

    print("Current :", get_current_sequence())

    print("Next :", get_next_sequence())

    print("Current :", get_current_sequence())

    reset_sequence()

    print("After Reset :", get_current_sequence())