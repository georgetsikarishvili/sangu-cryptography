import base64
import string
from itertools import permutations


def detailed_caesar_analysis(ciphertext):
    """Perform detailed Caesar cipher analysis."""
    print(f"\nCiphertext: {ciphertext}")
    print("Brute force results:")
    print("-" * 40)

    for shift in range(26):
        plaintext = ''
        for char in ciphertext.lower():
            if char in string.ascii_lowercase:
                shifted = (ord(char) - ord('a') - shift) % 26
                plaintext += chr(shifted + ord('a'))
            else:
                plaintext += char

        # Highlight likely English words
        english_words = ['rescue', 'secure', 'cipher', 'crypto', 'key', 'code']
        highlight = " ***" if plaintext in english_words else ""
        print(f"Shift {shift:2d}: {plaintext}{highlight}")


def manual_xor_decryption(ciphertext_bytes, key):
    """Show detailed XOR decryption process."""
    print(f"\nXOR Decryption Details:")
    print(f"Ciphertext length: {len(ciphertext_bytes)} bytes")
    print(f"Key: '{key}' (length: {len(key)})")
    print(f"Key bytes: {[ord(c) for c in key]}")
    print()

    key_bytes = key.encode('ascii')
    result = []

    print("Byte-by-byte XOR:")
    print("Idx | Ct Hex | Ct Dec | Key Char | Key Dec | XOR Hex | XOR Dec | Char")
    print("-" * 70)

    for i in range(min(26, len(ciphertext_bytes))):
        ct_byte = ciphertext_bytes[i]
        key_byte = key_bytes[i % len(key_bytes)]
        xor_result = ct_byte ^ key_byte
        key_char = key[i % len(key_bytes)]

        print(
            f"{i:3d} |   {ct_byte:02x}   |  {ct_byte:3d}   |    {key_char}     |   {key_byte:3d}   |    {xor_result:02x}   |   {xor_result:3d}   |  {chr(xor_result) if 32 <= xor_result <= 126 else '?'}")

        result.append(xor_result)

    # Decrypt full message
    full_decrypted = bytearray()
    for i in range(len(ciphertext_bytes)):
        full_decrypted.append(ciphertext_bytes[i] ^ key_bytes[i % len(key_bytes)])

    return full_decrypted.decode('ascii', errors='ignore')


def main_detailed():
    print("=" * 60)
    print("XOR Encryption/Decryption Challenge - Detailed Solution")
    print("=" * 60)

    # Step 1: Caesar Cipher
    print("\nSTEP 1: Caesar Cipher Brute Force")
    print("=" * 40)

    ciphertext = "mznxpz"
    detailed_caesar_analysis(ciphertext)

    # We know the answer is "rescue" at shift 21
    caesar_result = "rescue"
    print(f"\n✓ Identified Caesar decryption: '{caesar_result}' at shift 21")

    # Step 2: Anagram
    print("\nSTEP 2: Anagram Solution")
    print("=" * 40)
    print(f"Decrypted word: '{caesar_result}'")
    print("Possible anagrams related to cryptography:")

    crypto_terms = {
        'rescue': ['secure', 'recuse', 'cereus'],
        'secure': ['rescue', 'recuse', 'cereus']
    }

    for term in crypto_terms.get(caesar_result, []):
        print(f"  - {term}")

    passphrase = "secure"
    print(f"\n✓ Selected passphrase: '{passphrase}' (fundamental cryptography concept)")

    # Step 3: XOR Decryption
    print("\nSTEP 3: XOR Decryption")
    print("=" * 40)

    ct_b64 = "Jw0KBlIMAEUXHRdFKyoxVRENEgkPEBwCFkQ="
    print(f"Base64 ciphertext: {ct_b64}")

    # Decode base64
    ct_bytes = base64.b64decode(ct_b64)
    print(f"Decoded bytes (hex): {ct_bytes.hex()}")
    print(f"Decoded bytes (decimal): {list(ct_bytes)}")

    # XOR decrypt with detailed analysis
    plaintext = manual_xor_decryption(ct_bytes, passphrase)

    print(f"\n✓ Final decrypted message: '{plaintext}'")

    # Verification
    print("\n" + "=" * 60)
    print("FINAL RESULTS:")
    print(f"Caesar ciphertext: {ciphertext}")
    print(f"Caesar decrypted: {caesar_result}")
    print(f"Passphrase: {passphrase}")
    print(f"Final message: {plaintext}")
    print("=" * 60)


if __name__ == "__main__":
    main_detailed()
