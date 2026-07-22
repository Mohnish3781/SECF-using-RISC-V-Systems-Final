# crypto_utils.py

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ===========================
# Constants
# ===========================

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16

PBKDF2_ITERATIONS = 1000000
KEY_SIZE = 32       # AES-256


# ===========================
# Key Derivation
# ===========================

def derive_key(password: str, salt: bytes):
    """
    Derives a 256-bit AES key from password and salt.
    """

    return PBKDF2(
        password.encode("utf-8"),
        salt,
        dkLen=KEY_SIZE,
        count=PBKDF2_ITERATIONS
    )


# ===========================
# Salt Generation
# ===========================

def generate_salt():
    """
    Generates a random 128-bit salt.
    """

    return get_random_bytes(SALT_SIZE)


# ===========================
# Nonce Generation
# ===========================

def generate_nonce():
    """
    Generates a random 96-bit nonce.
    AES-GCM recommends 12-byte nonce.
    """

    return get_random_bytes(NONCE_SIZE)


# ===========================
# Encrypt Payload
# ===========================

def encrypt_payload(payload: bytes,
                    password: str,
                    aad: bytes):
    """
    Encrypt payload using AES-256-GCM.

    aad = Authenticated header.

    Returns:
        salt
        nonce
        ciphertext
        tag
    """

    salt = generate_salt()

    key = derive_key(password, salt)

    nonce = generate_nonce()

    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=nonce
    )

    # Authenticate header
    cipher.update(aad)

    ciphertext, tag = cipher.encrypt_and_digest(payload)

    return salt, nonce, ciphertext, tag


# ===========================
# Decrypt Payload
# ===========================

def decrypt_payload(ciphertext: bytes,
                    password: str,
                    salt: bytes,
                    nonce: bytes,
                    tag: bytes,
                    aad: bytes):
    """
    Verify authentication and decrypt payload.
    """

    key = derive_key(password, salt)

    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=nonce
    )

    # Authenticate header
    cipher.update(aad)

    plaintext = cipher.decrypt_and_verify(
        ciphertext,
        tag
    )

    return plaintext


# ===========================
# Authentication Verification
# ===========================

def verify_packet(ciphertext: bytes,
                  password: str,
                  salt: bytes,
                  nonce: bytes,
                  tag: bytes,
                  aad: bytes):
    """
    Returns True if authentication succeeds.
    """

    try:

        decrypt_payload(
            ciphertext,
            password,
            salt,
            nonce,
            tag,
            aad
        )

        return True

    except ValueError:

        return False


# ===========================
# Utility Functions
# ===========================

def bytes_to_hex(data: bytes):

    return data.hex()


def hex_to_bytes(data: str):

    return bytes.fromhex(data)