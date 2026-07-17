# Threat Model: Aegis Vault

## 1. Adversary Profile

| Capability | Assumed |
|------------|---------|
| Read disk contents | Yes |
| Know vault directory path | Yes |
| Observe file sizes and access patterns | Yes |
| Know the vault format (nonce \|\| ct \|\| tag) | Yes |
| Modify or delete files on disk | Yes |
| Know the namespace and item_id | Yes |
| **Know the passphrase** | **No** |
| **Access running process memory** | **No** |
| **Perform chosen-ciphertext attacks online** | **Limited** |

## 2. Security Properties

### 2.1 Confidentiality

**Claim:** An adversary who obtains all `.enc` files and `manifest.enc` cannot recover any plaintext without the passphrase.

**Argument:** Each file is encrypted under a unique DEK. DEKs are wrapped under a Master Key derived via PBKDF2-HMAC-SHA256 (600K iterations). The Master Key exists only in memory during the session. The manifest is itself encrypted under the Master Key with AAD binding.

**Reduction:** Breaking confidentiality requires either:
1. Brute-forcing the passphrase (600K PBKDF2 iterations per guess)
2. Breaking AES-256-GCM (2^128 security margin)
3. Breaking ChaCha20-Poly1305 (2^128 security margin)

### 2.2 Integrity

**Claim:** Any modification to an `.enc` file or `manifest.enc` is detected and rejected.

**Argument:** AEAD authentication tags cover both ciphertext and AAD. AAD binds each blob to its namespace and item_id. Tag verification happens before decryption.

### 2.3 Namespace Isolation

**Claim:** A file stored in namespace A cannot be loaded from namespace B.

**Argument:** AAD = `b"aegis_ns:" + b"namespace:item_id"`. Decrypting with wrong AAD produces `InvalidTag`.

### 2.4 Atomic Write Guarantee

**Claim:** A crash during write never corrupts an existing file.

**Argument:** Write pattern: `.tmp` -> `write` -> `flush` -> `fsync` -> `os.replace()`. The `os.replace()` call is atomic on POSIX and Windows NTFS. Before replace, only `.tmp` exists. After replace, only the complete file exists.

### 2.5 Secure Deletion

**Claim:** Deleted files cannot be recovered via filesystem forensic tools.

**Argument:** Before `unlink()`, the file is overwritten with `os.urandom(length)` bytes. The overwritten data is indistinguishable from random. **Limitation:** This does not protect against journaling filesystems that retain old blocks, or SSD wear-leveling that may remap blocks.

## 3. What This Model Does NOT Cover

| Threat | Status |
|--------|--------|
| Evil maid attack (physical access to running machine) | Out of scope |
| Memory dump of running process | Out of scope |
| Side-channel attacks (timing, cache) | Out of scope |
| Filesystem journal recovery | Partial mitigation (secure delete) |
| SSD wear-leveling remapping | Not mitigated |
| Passphrase brute-force with GPU cluster | Mitigated by PBKDF2 cost |
| Denial of service | Not addressed |

## 4. Trust Assumptions

1. The Python `os.urandom()` CSPRNG is not compromised
2. The `cryptography` library's AES-GCM/ChaCha20 implementations are correct
3. The OS `fsync()` call actually flushes to persistent storage
4. The user chooses a passphrase with sufficient entropy
