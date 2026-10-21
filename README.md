# 🛡️ File Safe — AES-256-GCM Desktop Vault

**File Safe** is a standalone Windows desktop vault application built with Python, `CustomTkinter`, and the `cryptography` library. It provides authenticated streaming encryption, zero-knowledge filename obfuscation, an in-memory (RAM-only) file previewer, and automated plaintext file shredding.

---

## 🔒 Security Architecture

File Safe is engineered around strict cryptographic and memory-safety guarantees:

1. **Authenticated Encryption (`AES-256-GCM`):**
   - Every file is encrypted using AES-256 in Galois/Counter Mode (GCM), providing both confidentiality and cryptographic integrity verification.
   - Generates a fresh, cryptographically secure 12-byte IV/nonce (`os.urandom(12)`) and 16-byte salt (`os.urandom(16)`) for every single encryption operation.

2. **Hardened Key Derivation (`PBKDF2-HMAC-SHA256`):**
   - Derives a 256-bit (32-byte) key from the master password using 600,000 iterations of PBKDF2-HMAC-SHA256, mitigating offline GPU brute-force attacks.

3. **Custom Binary File Format & Constant-Memory Streaming:**
   - Binary header layout: `[Salt (16B)] + [IV (12B)] + [GCM Auth Tag (16B)] + [Ciphertext]` (44-byte header).
   - Streams encryption and decryption in **64 KB chunks**, allowing multi-gigabyte files to be processed with an $O(1)$ memory footprint.
   - During file decryption, output is written to an isolated staging file and only atomically moved to the target destination *after* the 16-byte GCM authentication tag is verified. If tampering or a wrong password is detected, the unverified output is immediately unlinked.

4. **Zero-Knowledge Vault & Filename Obfuscation:**
   - Encrypted files are moved into an internal `Vault/` directory under randomized UUID filenames (`<uuid4>.fsafe`) so directory listings do not leak original filenames.
   - Original filenames, sizes, and source paths are stored inside an AES-256-GCM encrypted catalog (`Vault/vault_index.fsafe`).

5. **Zero Key Persistence & RAM-Only Previewer:**
   - Master passwords and decrypted preview buffers are held in mutable `bytearray` objects and explicitly zeroed out (`buffer[i] = 0`) upon closing a preview, locking the vault, or hitting the **5-minute inactivity auto-lock watchdog**.
   - Built-in **View in RAM** modal decrypts text/code files and images (`PIL.Image` via `io.BytesIO`) strictly in memory (capped at 50 MB) without writing temporary plaintext files to disk.

6. **Secure Plaintext Shredder (`shredder.py`):**
   - Verifies exclusive OS file locks prior to modification.
   - Overwrites the original file's exact byte length in-place using `os.urandom()`, flushes OS buffers to disk via `os.fsync()`, renames the file to a random hex string to scrub NTFS `$MFT` filename metadata, and unlinks it.
   - Includes a transparent user advisory regarding SSD/NVMe Flash Translation Layer (FTL) wear-leveling.

---

## 📂 Project Structure

```text
├── app.py                  # CustomTkinter GUI, RAM previewer, & 5-minute auto-lock watchdog
├── crypto_engine.py        # AES-256-GCM streaming cipher & PBKDF2-HMAC-SHA256 key derivation
├── shredder.py             # CSPRNG file overwrite, fsync, MFT rename obfuscation, & unlinking
├── test_crypto_engine.py   # Unit tests for encryption, decryption, bit-flip tampering, & wrong password
├── test_shredder.py        # Unit tests for file locking, byte overwriting, & deletion
├── build_exe.py            # Automated test runner, PyInstaller builder, & SHA-256 manifest generator
├── FileSafe.spec           # Hardened PyInstaller --onedir specification (UPX disabled)
├── requirements.txt        # Pinned Python dependencies
└── .gitignore              # Excludes Vault/, .fsafe files, virtual environments, and build artifacts