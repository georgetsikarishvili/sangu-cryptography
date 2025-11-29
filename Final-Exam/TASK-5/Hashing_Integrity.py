import hashlib
import json
import os


def calculate_hashes(file_path):
    """
    Reads a file in binary mode and computes MD5, SHA-1, and SHA-256 hashes.
    """
    # Initialize the hash objects
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    try:
        with open(file_path, 'rb') as f:
            # Read the file in chunks to handle large files efficiently
            while chunk := f.read(8192):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)

        # Return a dictionary of the hexadecimal digests
        return {
            "md5": md5_hash.hexdigest(),
            "sha1": sha1_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest()
        }
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        return None


def save_to_json(data, json_filename):
    """Saves the hash dictionary to a JSON file."""
    with open(json_filename, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"[+] Hashes saved to {json_filename}")


def check_integrity(target_file, json_record):
    """
    Compares the current hashes of a file against a saved JSON record.
    """
    print(f"\n--- Checking Integrity for: {target_file} ---")

    # 1. Load the "known good" hashes
    try:
        with open(json_record, 'r') as f:
            stored_hashes = json.load(f)
    except FileNotFoundError:
        print("Error: JSON record not found.")
        return

    # 2. Calculate current hashes of the target file
    current_hashes = calculate_hashes(target_file)
    if not current_hashes:
        return

    # 3. Compare
    integrity_pass = True
    for algo, digest in stored_hashes.items():
        if current_hashes[algo] == digest:
            print(f"[{algo.upper()}] Match: {digest}")
        else:
            print(f"[{algo.upper()}] MISMATCH!")
            print(f"  Expected: {digest}")
            print(f"  Found:    {current_hashes[algo]}")
            integrity_pass = False

    # 4. Final Verdict
    if integrity_pass:
        print(f"RESULT: PASS (File is authentic)")
    else:
        print(f"RESULT: FAIL (WARNING: File has been tampered with!)")


def main():
    # --- STEP 1: Create Original File ---
    original_file = "original.txt"
    json_file = "hashes.json"

    content = "This is the original, secure message.\nConfidential Data inside."
    with open(original_file, 'w') as f:
        f.write(content)
    print(f"[+] Created {original_file}")

    # --- STEP 2: Compute & Store Hashes ---
    hashes = calculate_hashes(original_file)
    save_to_json(hashes, json_file)

    # --- STEP 3: Verify Original (Should Pass) ---
    check_integrity(original_file, json_file)

    # --- STEP 4: Simulate Tampering ---
    tampered_file = "tampered.txt"
    with open(tampered_file, 'w') as f:
        # We change the content slightly (e.g., changing 'secure' to 'hacked')
        f.write(content.replace("secure", "hacked"))
    print(f"\n[!] Simulated tampering: Created {tampered_file}")

    # --- STEP 5: Verify Tampered File against Original Record (Should Fail) ---
    # We are checking if 'tampered.txt' matches the signature of the original file
    check_integrity(tampered_file, json_file)


if __name__ == "__main__":
    main()