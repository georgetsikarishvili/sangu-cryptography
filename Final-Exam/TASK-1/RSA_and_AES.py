import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding


def generate_rsa_keys():
    """
    User A: Generates RSA private and public keys.
    """
    print("--- User A: Generating RSA Key Pair ---")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def create_initial_message(filename="message.txt"):
    """
    Helper: Creates the initial secret message file.
    """
    secret_text = "This is a top secret message for User A's eyes only."
    with open(filename, "w") as f:
        f.write(secret_text)
    print(f"File created: {filename}")
    return secret_text.encode('utf-8')


def encrypt_message_aes(message_bytes):
    """
    User B: Encrypts the actual message using AES-256.
    """
    print("--- User B: Encrypting message with AES-256 ---")
    # Generate a random 256-bit (32 byte) key
    aes_key = os.urandom(32)
    # Generate a random 128-bit (16 byte) IV
    iv = os.urandom(16)

    # Pad the data (AES requires blocks of 128 bits)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(message_bytes) + padder.finalize()

    # Encrypt
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return aes_key, iv, ciphertext


def encrypt_aes_key_rsa(aes_key, public_key):
    """
    User B: Encrypts the AES key using User A's Public RSA Key.
    """
    print("--- User B: Encrypting AES key with RSA ---")
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key


def decrypt_aes_key_rsa(encrypted_aes_key, private_key):
    """
    User A: Decrypts the AES key using their Private RSA Key.
    """
    print("--- User A: Decrypting AES key with RSA ---")
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key


def decrypt_message_aes(aes_key, iv, ciphertext):
    """
    User A: Decrypts the message using the recovered AES key.
    """
    print("--- User A: Decrypting message body with AES ---")
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the data
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode('utf-8')


def main():
    # 1. Setup: Create the message file
    original_message_bytes = create_initial_message("message.txt")

    # 2. User A: Generate Keys
    user_a_private_key, user_a_public_key = generate_rsa_keys()

    # 3. User B: Encrypt Message (Hybrid Approach)
    # 3a. Encrypt message payload with AES
    aes_key, iv, ciphertext = encrypt_message_aes(original_message_bytes)

    # 3b. Encrypt the AES key with RSA
    encrypted_aes_key = encrypt_aes_key_rsa(aes_key, user_a_public_key)

    # 4. Storage: Save artifacts to disk (Simulating transmission)
    # We prepend the IV to the ciphertext for storage, as it is needed for decryption
    # and does not need to be secret, just unique.
    with open("encrypted_message.bin", "wb") as f:
        f.write(iv + ciphertext)
    print("File generated: encrypted_message.bin (Contains IV + AES Ciphertext)")

    with open("aes_key_encrypted.bin", "wb") as f:
        f.write(encrypted_aes_key)
    print("File generated: aes_key_encrypted.bin (Contains RSA Encrypted AES Key)")

    # 5. User A: Receive and Decrypt

    # Read files from disk
    with open("aes_key_encrypted.bin", "rb") as f:
        loaded_encrypted_key = f.read()

    with open("encrypted_message.bin", "rb") as f:
        loaded_data = f.read()
        loaded_iv = loaded_data[:16]  # First 16 bytes are IV
        loaded_ciphertext = loaded_data[16:]  # Rest is ciphertext

    # Decrypt AES Key first
    decrypted_aes_key = decrypt_aes_key_rsa(loaded_encrypted_key, user_a_private_key)

    # Decrypt Message using the decrypted AES Key
    decrypted_message = decrypt_message_aes(decrypted_aes_key, loaded_iv, loaded_ciphertext)

    # 6. Save Decrypted Output
    with open("decrypted_message.txt", "w") as f:
        f.write(decrypted_message)
    print(f"File generated: decrypted_message.txt")

    # Verification
    print("\n--- Verification ---")
    print(f"Original: {original_message_bytes.decode('utf-8')}")
    print(f"Decrypted: {decrypted_message}")
    print("Process Complete.")


if __name__ == "__main__":
    # Ensure cryptography is installed: pip install cryptography
    main()