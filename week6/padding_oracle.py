from binascii import unhexlify, hexlify
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16 # AES block size is 16 bytes
KEY = b"this_is_16_bytes"

# Ciphertext = IV + encrypted blocks (from check decrypt.py success)
CIPHERTEXT_HEX = (
    "746869735f69735f31365f6279746573"
    "9404628dcdf3f003482b3b0648bd920b"
    "3f60e13e89fa6950d3340adbbbb41c12"
    "b3d1d97ef97860e9df7ec0d31d13839a"
    "e17b3be8f69921a07627021af16430e1"
)

def padding_oracle(ciphertext: bytes) -> bool:
    """Returns True if the ciphertext decrypts with valid padding, False
    otherwise."""
    if len(ciphertext) % BLOCK_SIZE != 0:
        return False

    try:
        iv = ciphertext[:BLOCK_SIZE]
        ct = ciphertext[BLOCK_SIZE:]
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()

        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadder.update(decrypted)
        unpadder.finalize()
        return True
    except (ValueError, TypeError):
        return False
#TASK 1
""" 
1. The padding oracle tries to decrypt the ciphertext and then remove PKCS#7 padding. If unpadding succeeds, padding is valid; if an exception is raised, padding is invalid.

2. The IV ensures CBC mode produces different ciphertexts for identical plaintexts by randomizing the encryption of the first block.

3. Because AES is a block cipher that operates on 16-byte blocks, the ciphertext (excluding the IV) must always be a whole number of blocks—i.e., a multiple of 16 bytes.
"""

#TASK 2
def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    """Split data into blocks of the specified size."""
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]

#TASK 3
def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:
    """Decrypt a single block using the padding oracle attack. Returns the decrypted plaintext block."""
    n = len(prev_block)
    plaintext = bytearray(n)
    intermediate = bytearray(n)
    for pad_len in range(1, n + 1):
        pos = n - pad_len
        suffix = bytearray((intermediate[j] ^ pad_len) for j in range(pos + 1, n))
        found = False
        for guess in range(256):
            forged_prev = bytearray(b"\x00" * pos)
            forged_prev.append(guess)
            forged_prev.extend(suffix)
            test_ct = bytes(forged_prev) + target_block
            if padding_oracle(test_ct):
                inter = guess ^ pad_len
                intermediate[pos] = inter
                plaintext[pos] = inter ^ prev_block[pos]
                found = True
                break
        if not found:
            raise ValueError(f"Failed to recover byte at position {pos}")
    return bytes(plaintext)

#TASK 4
def padding_oracle_attack(ciphertext: bytes) -> bytes:
    """Perform the padding oracle attack on the entire ciphertext."""
    blocks = split_blocks(ciphertext, BLOCK_SIZE)
    if len(blocks) < 2:
        raise ValueError("Ciphertext must include IV + at least one block")
    recovered = []
    for i in range(1, len(blocks)):
        pt_block = decrypt_block(blocks[i - 1], blocks[i])
        recovered.append(pt_block)
    return b"".join(recovered)

def unpad_and_decode(plaintext: bytes) -> str:
    """Attempt to unpad and decode the plaintext."""
    try:
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadded = unpadder.update(plaintext) + unpadder.finalize()
    except Exception:
        return f"(invalid padding) hex={hexlify(plaintext).decode()}"
    try:
        return unpadded.decode("utf-8")
    except UnicodeDecodeError:
        return f"(non-UTF8) hex={hexlify(unpadded).decode()}"


if __name__ == "__main__":
    try:
        ciphertext = unhexlify(CIPHERTEXT_HEX)
        print(f"[*] Ciphertext length: {len(ciphertext)} bytes")
        print(f"[*] IV: {ciphertext[:BLOCK_SIZE].hex()}")

        recovered = padding_oracle_attack(ciphertext)

        print("\n[+] Decryption complete!")
        print(f"  Recovered plaintext (raw bytes): {recovered}")
        print(f"  Hex: {recovered.hex()}")

        decoded = unpad_and_decode(recovered)
        print("\n  Final plaintext:")
        print(decoded)

    except Exception as e:
        print(f"[*] Error occurred: {e}")