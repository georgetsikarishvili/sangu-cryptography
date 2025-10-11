def caesar_decrypt(ciphertext, shift):
    """
    Decrypt Caesar cipher with given shift value
    """
    plaintext = ""

    for char in ciphertext:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            decrypted_char = chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
            plaintext += decrypted_char
        else:
            plaintext += char

    return plaintext


def detect_caesar_shift(ciphertext):
    """
    Automatically detect the most likely Caesar shift using English word patterns
    """
    # Common English words to check for
    common_words = ['the', 'and', 'is', 'in', 'it', 'to', 'of', 'a', 'i', 'you', 'he', 'she', 'we', 'are']

    best_shift = 0
    best_score = 0

    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift).lower()
        words = decrypted.split()

        # Score based on common words
        score = 0
        for word in words:
            # Remove punctuation for better matching
            clean_word = ''.join(char for char in word if char.isalpha())
            if clean_word in common_words:
                score += 1

        # Also check for reasonable word lengths
        reasonable_lengths = sum(
            1 for word in words if 1 <= len(''.join(char for char in word if char.isalpha())) <= 12)
        score += reasonable_lengths * 0.1

        if score > best_score:
            best_score = score
            best_shift = shift

    return best_shift


def brute_force_with_detection(ciphertext):
    """
    Brute-force but highlight the most likely result
    """
    detected_shift = detect_caesar_shift(ciphertext)

    print("Brute-force attack results:")
    print("=" * 50)

    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)

        if shift == detected_shift:
            print(f"Shift {shift:2d}: {decrypted}  ← AUTO-DETECTED (most likely)")
        else:
            print(f"Shift {shift:2d}: {decrypted}")


def main():
    ciphertext = "Hvs Eiwqy Pfckb Tcl Xiadg Cjsf Hvs Zonm Rcu."

    brute_force_with_detection(ciphertext)

    print("\n" + "=" * 50)
    print(f"Automatically detected shift: {detect_caesar_shift(ciphertext)}" + "\n" + "=" * 50)
    print(f"Decrypted text: {caesar_decrypt(ciphertext, detect_caesar_shift(ciphertext))}")

if __name__ == "__main__":
    main()
