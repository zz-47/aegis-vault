# Aegis Vault

**Zero-cloud encrypted file storage with envelope encryption.**

Aegis Vault encrypts your files locally using a three-layer envelope encryption architecture. Your passphrase never leaves your machine. No cloud. No subscription. No telemetry.

## What It Does

```
Your File → JSON serialize → Encrypt with DEK → Encrypt DEK with Master Key → Write .enc to disk
                                                        ↑
                                              Derived from your passphrase
                                              via PBKDF2-HMAC-SHA256 (600K iterations)
```

Each file gets its own Data Encryption Key (DEK). The DEK is wrapped under a Master Key derived from your passphrase. The Master Key never touches disk — only the wrapped DEKs do. The entire manifest (mapping files to DEKs) is itself encrypted.

## Security Properties

| Property | Guarantee |
|----------|-----------|
| **At-rest encryption** | AES-256-GCM or ChaCha20-Poly1305 (auto-selected) |
| **Key derivation** | PBKDF2-HMAC-SHA256, 600K iterations (OWASP 2023 minimum) |
| **Envelope encryption** | Per-file DEK wrapped under Master Key |
| **Tamper detection** | AEAD auth tags on every blob |
| **Atomic writes** | .tmp → fsync → os.replace (crash-safe) |
| **Secure deletion** | Overwrite with random bytes before unlink |
| **Namespace isolation** | AAD binding prevents cross-namespace file swaps |

## Quick Start

```bash
pip install aegis-vault

# Initialize a vault
aegis init --passphrase "your-secret" --vault ./my-vault

# Store a file
aegis store --vault ./my-vault --namespace personal --id doc1 --file secret.txt

# Retrieve it
aegis retrieve --vault ./my-vault --namespace personal --id doc1 --output restored.txt

# List stored items
aegis list --vault ./my-vault --namespace personal
```

## Docker

```bash
docker build -t aegis-vault .
docker run -v $(pwd)/vault:/vault aegis-vault init --passphrase "secret" --vault /vault
```

## Python API

```python
from aegis.crypt_storage import LocalEncryptedStorage

store = LocalEncryptedStorage("./my-vault", "your-passphrase")
store.save("personal", "doc1", {"content": "secret data", "type": "note"})
data = store.load("personal", "doc1")
```

## Architecture

```
┌─────────────────────────────────────┐
│         LocalEncryptedStorage       │  ← User API: save/load/delete
│  (namespace routing, atomic write)  │
├─────────────────────────────────────┤
│           KeyManager                │  ← Envelope encryption: MK → DEK wrap
│  (PBKDF2, DEK cache, manifest)     │
├─────────────────────────────────────┤
│           AeadCipher                │  ← Raw AEAD: AES-GCM / ChaCha20
│  (encrypt, decrypt, combined blob)  │
└─────────────────────────────────────┘
```

## Namespaces

| Namespace | Purpose |
|-----------|---------|
| `personal` | Personal documents, notes |
| `work` | Work-related files |
| `archive` | Long-term storage |

# RUN-TESTS

Run test in your terminal :

```bash
python -m pytest tests/ -v
```

## Benchmarks

Run benchmarks on your hardware:

```bash
python benchmarks/bench_cipher.py
```

## Research

See [docs/IMPLEMENTATION_PAPER.md](docs/IMPLEMENTATION_PAPER.md) for the security analysis.

## License

MIT
