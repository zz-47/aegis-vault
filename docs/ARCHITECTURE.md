# Architecture: Seal (Aegis Vault)

## 12-Module System

```
┌─────────────────────────────────────────────────────────────────┐
│                          cli.py                                 │
│                    Click CLI interface                           │
├─────────────────┬───────────────────┬───────────────────────────┤
│  crypt_storage  │      audit        │        canary             │
│  AegisVault     │  SHA-256 chain    │  Decoy detection          │
│  save/load/del  │  append-only log  │  entropy monitoring       │
├─────────────────┼───────────────────┼───────────────────────────┤
│  sharing        │      report       │       biometric           │
│  X25519 stanzas │  SOC2/HIPAA/      │  keyring + fingerprint    │
│  multi-user     │  GDPR/ISO27001    │  Windows Hello            │
├─────────────────┴───────────────────┴───────────────────────────┤
│                      key_manager.py                             │
│            PBKDF2 (600K) → DEK wrap/unwrap → manifest           │
├─────────────────────────────────────────────────────────────────┤
│                       cipher.py                                 │
│            AES-256-GCM / ChaCha20-Poly1305 AEAD                 │
├─────────────────────────────────────────────────────────────────┤
│                      _errors.py                                 │
│            9 custom exception classes                           │
└─────────────────────────────────────────────────────────────────┘
```

## Layer Stack

```
┌──────────────────────────────────────────────────┐
│              LocalEncryptedStorage                │
│  ┌─────────────┬──────────────┬───────────────┐  │
│  │  save()     │  load()      │  delete()     │  │
│  │  list()     │              │               │  │
│  └──────┬──────┴──────┬───────┴───────┬───────┘  │
│         │             │               │           │
│  ┌──────▼─────────────▼───────────────▼───────┐  │
│  │           KeyManager                        │  │
│  │  ┌─────────────┬────────────────────────┐  │  │
│  │  │ derive_master_key()                   │  │  │
│  │  │ generate_dek() / wrap_dek()           │  │  │
│  │  │ unwrap_dek() / get_dek()             │  │  │
│  │  │ export/import_encrypted_manifest()    │  │  │
│  │  └─────────────┬────────────────────────┘  │  │
│  │                │                            │  │
│  │  ┌─────────────▼────────────────────────┐  │  │
│  │  │           AeadCipher                  │  │  │
│  │  │  encrypt() / decrypt()               │  │  │
│  │  │  encrypt_combined() / decrypt_combined│  │  │
│  │  └──────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```

## Data Flow: save()

```
1. Validate namespace ∈ {personal, work, archive}
2. Check if item_id already has a DEK
   ├─ YES → reuse existing DEK
   └─ NO  → generate new DEK → wrap under Master Key → add to manifest
3. JSON-serialize the data dict
4. Construct AAD = b"aegis_ns:" + b"namespace:item_id"
5. Encrypt(serialized_data, dek, aad) → blob
6. Atomic write: .tmp → flush → fsync → os.replace
7. If manifest changed → save manifest (same atomic pattern)
```

## Data Flow: load()

```
1. Validate namespace
2. Read .enc file from disk
3. Look up DEK via KeyManager (cache → manifest → unwrap)
4. Construct AAD = b"aegis_ns:" + b"namespace:item_id"
5. Decrypt(blob, dek, aad) → serialized_data
6. JSON-deserialize → return dict
```

## On-Disk Layout

```
vault/
├── keys/
│   └── manifest.enc          # salt(16) || encrypted(JSON{items: {id: {dek, ns, created}}})
├── personal/
│   ├── doc1.enc              # nonce(12) || ciphertext || tag(16)
│   └── doc2.enc
├── work/
│   └── report.enc
└── archive/
    └── old_data.enc
```

## Blob Format

```
┌──────────┬────────────────────┬──────────┐
│ nonce    │ ciphertext         │ auth_tag │
│ (12 B)   │ (len(data) B)      │ (16 B)   │
└──────────┴────────────────────┴──────────┘
```

## Manifest Format

```
┌──────┬─────────────────────────────────────┐
│ salt │ encrypted JSON payload              │
│(16B) │ nonce(12) || ct || tag(16)          │
└──────┴─────────────────────────────────────┘
```

## AAD Domain Separation

| Context | AAD Value |
|---------|-----------|
| DEK wrapping | `b"aegis_dek_wrap_v1" + item_id_bytes` |
| Manifest encryption | `b"aegis_manifest_v1"` |
| File encryption | `b"aegis_ns:" + b"namespace:item_id"` |

Different AAD values for different purposes prevent ciphertext relocation attacks.

## Modules

| Module | LOC | Role |
|--------|-----|------|
| `cipher.py` | 134 | AEAD encrypt/decrypt (AES-GCM, ChaCha20) |
| `key_manager.py` | 200 | PBKDF2 derivation, DEK wrap/unwrap, manifest I/O |
| `crypt_storage.py` | 166 | Vault facade: save/load/delete/list, atomic writes |
| `_errors.py` | 78 | 9 custom exception classes |
| `audit.py` | 133 | SHA-256 chained append-only audit log |
| `canary.py` | 180 | Ransomware canary decoy detection |
| `sharing.py` | 154 | X25519 key exchange for multi-user access |
| `biometric.py` | 113 | Windows Hello fingerprint + keyring integration |
| `report.py` | 236 | SOC 2 / HIPAA / GDPR / ISO 27001 report generation |
| `cli.py` | 2 | Click CLI interface (placeholder) |
| **Total** | **1,294** | |

## On-Disk Layout (Full)

```
vault/
├── keys/
│   ├── manifest.enc          # salt(16) || encrypted(JSON{items: {id: {dek, ns, created}}})
│   ├── audit.log             # NDJSON: {seq, ts, op, namespace, item_id, prev_hash, hash}
│   └── stanzas.json          # X25519 wrapped DEKs for shared users
├── personal/
│   ├── doc1.enc              # nonce(12) || ciphertext || tag(16)
│   └── doc2.enc
├── work/
│   └── report.enc
├── archive/
│   └── old_data.enc
└── .canaries/
    ├── canaries.json         # {name, path, original_hash, original_entropy}
    ├── passwords.xlsx        # Decoy file (512 bytes random)
    ├── financials.pdf        # Decoy file
    └── wallet.dat            # Decoy file
```

## Test Suite

108 tests across 10 files. See [tests/TEST_DOCUMENTATION.md](../tests/TEST_DOCUMENTATION.md) for the full indexed test catalog.

```bash
python -m pytest tests/ -v        # Run all 108 tests
python -m pytest tests/test_cipher.py -v  # Run one module
```
