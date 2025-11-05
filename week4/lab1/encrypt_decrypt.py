from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# 1. Create original message file
message = b"Ra Qeni Guduna Es?! :D :D"
with open("message.txt", "wb") as f:
    f.write(message)

# 2. Generate RSA Key Pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Write keys to files
with open("private.pem", "wb") as f:
    f.write(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))

with open("public.pem", "wb") as f:
    f.write(public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ))


# RSA Encryption
with open("message.txt", "rb") as f:
    plaintext = f.read()

rsa_encrypted = public_key.encrypt(
    plaintext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

with open("message_rsa_encrypted.bin", "wb") as f:
    f.write(rsa_encrypted)

# RSA Decryption
rsa_decrypted = private_key.decrypt(
    rsa_encrypted,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

with open("message_rsa_decrypted.txt", "wb") as f:
    f.write(rsa_decrypted)


# 3. AES-256 Encryption
aes_key = os.urandom(32)  # AES-256 key = 32 bytes
aes_iv = os.urandom(16)

with open("aes_key.bin", "wb") as f:
    f.write(aes_key)

with open("aes_iv.bin", "wb") as f:
    f.write(aes_iv)

cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv))
encryptor = cipher.encryptor()
aes_encrypted = encryptor.update(plaintext) + encryptor.finalize()

with open("message_aes_encrypted.bin", "wb") as f:
    f.write(aes_encrypted)

# AES Decryption
decryptor = cipher.decryptor()
aes_decrypted = decryptor.update(aes_encrypted) + decryptor.finalize()

with open("message_aes_decrypted.txt", "wb") as f:
    f.write(aes_decrypted)