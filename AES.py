import hashlib
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
def getpassword():
    password = input("Enter the password: ")
    return password
#encrpt the file
def encrypt_file(input_file, output_file, password):
    try:
        # Generate salt
        salt = get_random_bytes(16)

        # Derive 256-bit AES key
        key = PBKDF2(password.encode("utf-8"),
                     salt,
                     dkLen=32,
                     count=1000000)

        # Generate 12-byte nonce (recommended for GCM)
        nonce = get_random_bytes(12)

        # Create AES-GCM cipher
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        # Read plaintext
        with open(input_file, "rb") as infile:
            plaintext = infile.read()

        # Encrypt and generate authentication tag
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        # Save:
        # Salt (16 bytes)
        # Nonce (12 bytes)
        # Tag (16 bytes)
        # Ciphertext
        with open(output_file, "wb") as outfile:
            outfile.write(salt)
            outfile.write(nonce)
            outfile.write(tag)
            outfile.write(ciphertext)

        print("Encryption successful.")
        print("Encrypted file:", output_file)

    except FileNotFoundError:
        print("Input file not found.")
    except Exception as e:
        print("Encryption error:", e)
def decrypt_file(input_file, output_file, password):
    try:

        with open(input_file, "rb") as infile:

            # Read Salt
            salt = infile.read(16)

            # Read Nonce
            nonce = infile.read(12)

            # Read Authentication Tag
            tag = infile.read(16)

            # Remaining bytes are ciphertext
            ciphertext = infile.read()

        # Derive AES-256 key
        key = PBKDF2(password.encode("utf-8"),
                     salt,
                     dkLen=32,
                     count=1000000)

        # Create AES-GCM cipher
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        # Decrypt and verify authentication tag
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        with open(output_file, "wb") as outfile:
            outfile.write(plaintext)

        print("Decryption successful.")
        print("Authentication Verified.")

    except FileNotFoundError:
        print("Encrypted file not found.")

    except ValueError:
        print("Authentication failed!")
        print("Possible reasons:")
        print("- Wrong password")
        print("- File has been tampered")
        print("- Authentication tag mismatch")

    except Exception as e:
        print("Decryption error:", e)
def main():
    choice = input("Do you want to encrypt or decrypt a file? (e/d): ")
    print("choice =", repr(choice))
    if choice.lower() == 'e':
        input_file =r"C:\Users\Parthasarathy\OneDrive\Desktop\input_test_encrypt.txt"
        output_file =r"C:\Users\Parthasarathy\OneDrive\Desktop\output_test_encrypt.bin"
        password = getpassword()
        encrypt_file(input_file, output_file, password)
        print("File encrypted successfully.")
    elif choice.lower() == 'd':
        input_file1= r"C:\Users\Parthasarathy\OneDrive\Desktop\output_test_encrypt.bin"
        output_file2 = r"C:\Users\Parthasarathy\OneDrive\Desktop\input_test_encrypt.txt"
        password = getpassword()
        print("Reached decrypt section")
        print("input_file1 =", input_file1)
        print("exists =", os.path.exists(input_file1))
        decrypt_file(input_file1, output_file2, password)
        print("File decrypted successfully.")
    else:
        print("Invalid choice. Please enter 'e' for encryption or 'd' for decryption.")
if __name__ == "__main__":
    main()