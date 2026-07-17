# Architecture: Aegis Vault

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
