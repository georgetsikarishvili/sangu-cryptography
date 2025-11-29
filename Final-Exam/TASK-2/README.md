# Secure File Exchange: RSA + AES Hybrid Encryption

## Project Overview
This project demonstrates a secure file transfer protocol between Alice and Bob. It utilizes a **Hybrid Encryption** scheme:
1.  **AES-256 (Symmetric)** is used to encrypt the actual file data because it is fast and efficient for large payloads.
2.  **RSA-2048 (Asymmetric)** is used to securely exchange the AES key.

## Execution Flow

### 1. Key Generation (Bob)
Bob generates a pair of keys:
* `public.pem`: Shared with Alice.
* `private.pem`: Kept secret by Bob.

### 2. Encryption (Alice)
Alice performs the following steps:
1.  **Generate Session Key:** Creates a random 256-bit key ($K_{AES}$) and a 128-bit Initialization Vector (IV).
2.  **Encrypt Data:** Encrypts `alice_message.txt` using AES-CBC with $K_{AES}$.
    * $$C_{file} = AES_{encrypt}(Message, K_{AES})$$
    * Output: `encrypted_file.bin`
3.  **Encrypt Key:** Encrypts the $K_{AES}$ using Bob's Public Key ($K_{PUB}$).
    * $$C_{key} = RSA_{encrypt}(K_{AES}, K_{PUB})$$
    * Output: `aes_key_encrypted.bin`

### 3. Decryption (Bob)
Bob receives the encrypted file and the encrypted key:
1.  **Recover Session Key:** Bob uses his Private Key ($K_{PRIV}$) to decrypt the AES key.
    * $$K_{AES} = RSA_{decrypt}(C_{key}, K_{PRIV})$$
2.  **Decrypt Data:** Bob uses the recovered $K_{AES}$ (and the IV) to decrypt the file.
    * $$Message = AES_{decrypt}(C_{file}, K_{AES})$$
    * Output: `decrypted_message.txt`

### 4. Integrity Check
A SHA-256 hash is computed for both the original file and the decrypted file. If the hashes match, the integrity of the transmission is verified.

---

## Technical Comparison: AES vs. RSA

| Feature | AES (Advanced Encryption Standard) | RSA (Rivest–Shamir–Adleman) |
| :--- | :--- | :--- |
| **Type** | Symmetric (Same key for encrypt/decrypt) | Asymmetric (Public/Private key pair) |
| **Speed** | **Extremely Fast.** optimized for hardware. Suitable for encrypting gigabytes of data. | **Slow.** Mathematically intensive (modular exponentiation). Roughly 1,000x slower than AES. |
| **Input Size** | Can encrypt arbitrary amounts of data (using modes like CBC or GCM). | Limited by key size. A 2048-bit key can only encrypt ~190 bytes of data. |
| **Use Case** | Encrypting the actual payload (files, streams, database entries). | Key exchange (encrypting the AES key) and Digital Signatures. |
| **Security** | Security depends on keeping the shared key secret. | Security relies on the difficulty of factoring large prime numbers. |

**Why use Hybrid?**
We use Hybrid encryption to get the **speed of AES** with the **secure key distribution of RSA**. RSA allows Alice to send data to Bob without previously meeting to agree on a password.