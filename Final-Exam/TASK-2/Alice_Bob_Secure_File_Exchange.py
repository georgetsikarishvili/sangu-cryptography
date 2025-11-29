import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

def generate_rsa_keys():
    """Generates Bob's RSA Key Pair."""
    print("[-] Generating Bob's RSA Key Pair (2048 bit)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Save Private Key
    with open("private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save Public Key
    with open("public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    return private_key, public_key

def compute_hash(filename):
    """Computes SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filename, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

# ==========================================
# 1. SETUP & KEY GENERATION
# ==========================================
bob_private_key, bob_public_key = generate_rsa_keys()

# ==========================================
# 2. ALICE'S ACTIONS
# ==========================================
print("[-] Alice is creating the message...")
message_content = b"Confidential: The secure launch codes are 8844-alpha-tango."
with open("alice_message.txt", "wb") as f:
    f.write(message_content)

# Alice generates AES Session Key (32 bytes for AES-256) and IV (16 bytes)
aes_key = os.urandom(32)
iv = os.urandom(16)

# Save IV (Bob needs this to decrypt, usually sent in the clear)
with open("iv.bin", "wb") as f:
    f.write(iv)

print("[-] Alice encrypting file with AES-256...")
# Pad the data (AES block size is 128 bits)
padder = sym_padding.PKCS7(128).padder()
padded_data = padder.update(message_content) + padder.finalize()

# Encrypt data
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded_data) + encryptor.finalize()

with open("encrypted_file.bin", "wb") as f:
    f.write(ciphertext)

print("[-] Alice encrypting AES key with Bob's RSA Public Key...")
encrypted_aes_key = bob_public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

with open("aes_key_encrypted.bin", "wb") as f:
    f.write(encrypted_aes_key)

# ==========================================
# 3. BOB'S ACTIONS (DECRYPTION)
# ==========================================
print("\n[-] Bob received files. Decrypting...")

# Bob loads his private key (already in memory, but simulating load)
with open("private.pem", "rb") as f:
    loaded_private_key = serialization.load_pem_private_key(
        f.read(), password=None
    )

# 1. Decrypt the AES Key using RSA
with open("aes_key_encrypted.bin", "rb") as f:
    enc_key_from_file = f.read()

decrypted_aes_key = loaded_private_key.decrypt(
    enc_key_from_file,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# 2. Decrypt the File using the recovered AES Key
with open("iv.bin", "rb") as f:
    loaded_iv = f.read()
with open("encrypted_file.bin", "rb") as f:
    loaded_ciphertext = f.read()

cipher_decrypt = Cipher(algorithms.AES(decrypted_aes_key), modes.CBC(loaded_iv))
decryptor = cipher_decrypt.decryptor()
decrypted_padded_data = decryptor.update(loaded_ciphertext) + decryptor.finalize()

# Unpad the data
unpadder = sym_padding.PKCS7(128).unpadder()
original_message = unpadder.update(decrypted_padded_data) + unpadder.finalize()

with open("decrypted_message.txt", "wb") as f:
    f.write(original_message)

print(f"[-] Decrypted Content: {original_message.decode()}")

# ==========================================
# 4. INTEGRITY CHECK
# ==========================================
print("\n[-] Verifying Integrity (SHA-256)...")
hash_original = compute_hash("alice_message.txt")
hash_decrypted = compute_hash("decrypted_message.txt")

print(f"Original Hash:  {hash_original}")
print(f"Decrypted Hash: {hash_decrypted}")

if hash_original == hash_decrypted:
    print("SUCCESS: Integrity Verified. Files match.")
else:
    print("FAILURE: Hashes do not match.")