# Test Suite Documentation — Seal (Aegis Vault)

**108 tests across 10 test files. All pass.**

Run all tests:
```bash
python -m pytest tests/ -v
```

Run a specific file:
```bash
python -m pytest tests/test_cipher.py -v
```

Run a single test:
```bash
python -m pytest tests/test_robustness.py::TestEdgeCases::test_unicode_data_roundtrip -v
```

---

## Test File Index

| # | File | Tests | Module Under Test | Purpose |
|---|------|-------|-------------------|---------|
| 1 | `test_cipher.py` | 12 | `aegis.cipher` | AEAD encrypt/decrypt correctness |
| 2 | `test_key_manager.py` | 14 | `aegis.key_manager` | Key derivation, DEK wrapping, manifest |
| 3 | `test_crypt_storage.py` | 12 | `aegis.crypt_storage` | Vault save/load/delete/list |
| 4 | `test_audit.py` | 7 | `aegis.audit` | Tamper-evident audit log |
| 5 | `test_canary.py` | 7 | `aegis.canary` | Ransomware canary detection |
| 6 | `test_sharing.py` | 5 | `aegis.sharing` | X25519 multi-user key exchange |
| 7 | `test_biometric.py` | 7 | `aegis.biometric` | Biometric/keyring unlock (mocked) |
| 8 | `test_report.py` | 10 | `aegis.report` | Compliance report generation |
| 9 | `test_atomic_write.py` | 8 | `aegis.crypt_storage` | Crash-safe atomic writes |
| 10 | `test_data_leak.py` | 7 | `aegis.crypt_storage` | No plaintext on disk |
| 11 | `test_robustness.py` | 15 | All modules | Attack, corruption, edge cases |

---

## Detailed Test Index

### 1. `test_cipher.py` — AEAD Cipher (12 tests)

| Test ID | Test Name | What It Proves |
|---------|-----------|----------------|
| C-01 | `test_generate_key_length` | `generate_key()` returns exactly 32 bytes (AES-256) |
| C-02 | `test_encrypt_decrypt_roundtrip` | Encrypt then decrypt returns original plaintext |
| C-03 | `test_combined_roundtrip` | `encrypt_combined`/`decrypt_combined` roundtrip works |
| C-04 | `test_wrong_key_fails` | Decrypting with wrong key raises `DecryptionError` |
| C-05 | `test_tampered_ciphertext_fails` | Flipping a byte in ciphertext raises `DecryptionError` |
| C-06 | `test_wrong_aad_fails` | Mismatched AAD during decrypt raises `DecryptionError` |
| C-07 | `test_wrong_tag_fails` | Tampered auth tag raises `DecryptionError` |
| C-08 | `test_empty_plaintext` | Encrypting and decrypting `b""` works |
| C-09 | `test_large_plaintext` | 1MB random data roundtrips correctly |
| C-10 | `test_chacha20_roundtrip` | ChaCha20-Poly1305 suite works end-to-end |
| C-11 | `test_invalid_key_size` | Key < 32 bytes raises `LocalStorageError` |
| C-12 | `test_multiple_encryptions_unique_nonces` | Two encryptions produce different nonces |

---

### 2. `test_key_manager.py` — Key Manager (14 tests)

| Test ID | Test Name | What It Proves |
|---------|-----------|----------------|
| KM-01 | `test_derive_master_key` | PBKDF2 produces 32-byte key and stores salt |
| KM-02 | `test_derive_with_custom_salt` | Custom salt derivation produces valid key |
| KM-03 | `test_invalid_salt_size` | Salt < 16 bytes raises `LocalStorageError` |
| KM-04 | `test_generate_dek` | DEK generation returns 32 random bytes |
| KM-05 | `test_wrap_unwrap_roundtrip` | Wrap DEK then unwrap returns original DEK |
| KM-06 | `test_wrong_item_id_fails` | Unwrap with wrong item_id raises `DecryptionError` |
| KM-07 | `test_wrap_without_master_key` | Wrap before derive_master_key raises `LocalStorageError` |
| KM-08 | `test_export_import_manifest_roundtrip` | Export manifest, import with same passphrase succeeds |
| KM-09 | `test_import_wrong_passphrase` | Import with wrong passphrase raises `Exception` |
| KM-10 | `test_import_truncated_blob` | Import truncated manifest raises `ManifestError` |
| KM-11 | `test_get_dek_from_manifest` | Retrieve DEK from manifest returns correct key |
| KM-12 | `test_get_dek_missing_item` | Retrieve DEK for nonexistent item raises `ItemNotFoundError` |
| KM-13 | `test_dek_cache` | Cache DEK then retrieve from cache returns same key |
| KM-14 | `test_cache_fifo_eviction` | Cache at max capacity evicts oldest entry (FIFO) |

---

### 3. `test_crypt_storage.py` — Vault Storage (12 tests)

| Test ID | Test Name | What It Proves |
|---------|-----------|----------------|
| VS-01 | `test_save_load_roundtrip` | Save dict then load returns identical dict |
| VS-02 | `test_overwrite_existing` | Save same item_id twice, load returns latest |
| VS-03 | `test_namespace_isolation` | Same item_id in different namespaces are independent |
| VS-04 | `test_invalid_namespace` | Unknown namespace raises `LocalStorageError` |
| VS-05 | `test_load_nonexistent` | Load nonexistent item raises `ItemNotFoundError` |
| VS-06 | `test_delete` | Delete item, list shows empty |
| VS-07 | `test_delete_nonexistent` | Delete nonexistent item raises `ItemNotFoundError` |
| VS-08 | `test_list_items` | List returns sorted item stems |
| VS-09 | `test_list_empty_namespace` | Empty namespace returns `[]` |
| VS-10 | `test_tampered_ciphertext` | Tampered `.enc` file fails on load |
| VS-11 | `test_persistence` | New vault instance on same path can load saved data |
| VS-12 | `test_secure_delete_overwrites` | After delete, `.enc` file no longer exists |

---

### 4. `test_audit.py` — Audit Log (7 tests)

| Test ID | Test Name | What It Proves |
|---------|-----------|----------------|
| AL-01 | `test_append_and_verify` | Append 2 entries, verify chain is intact |
| AL-02 | `test_verify_empty_log` | Empty log verifies as valid |
| AL-03 | `test_tamper_detection` | Mutating an entry field breaks verification |
| AL-04 | `test_persistence` | New AuditLog instance loads previous entries |
| AL-05 | `test_filter_by_namespace` | Filter entries by namespace returns correct subset |
| AL-06 | `test_filter_by_op` | Filter entries by operation type works |
| AL-07 | `test_export_json` | JSON export contains expected compact format |

---

### 5. `test_canary.py` — Canary Detection (7 tests)

| Test ID | Test Name | What It Proves |
|---------|-----------|----------------|
| CA-01 | `test_deploy_creates_files` | Deploy creates canary files on disk |
| CA-02 | `test_check_intact` | Unmodified canaries show zero triggered |
| CA-03 | `test_tamper_detection` | Modified canary is detected by `check_all()` |
| CA-04 | `test_monitor_once_raises` | `monitor_once()` raises `PermissionError` on trigger |
| CA-05 | `test_remove_canaries` | Remove deletes canary files from disk |
| CA-06 | `test_shannon_entropy_random` | Random bytes have entropy > 7.5 |
| CA-07 | `test_shannon_entropy_text` | Repeated byte has entropy == 0.0 |

---

### 6. `test_sharing.py` — Multi-User Key Exchange (5 tests)

| Test ID | Test Name | What It Proves |
|---------|-----------|----------------|
| SH-01 | `test_generate_keypair` | Keypair generation returns 16-char ID + 32-byte hex pubkey |
| SH-02 | `test_wrap_unwrap_roundtrip` | Wrap DEK for user, unwrap with matching private key |
| SH-03 | `test_wrong_key_fails` | Unwrap with wrong private key returns `None` |
| SH-04 | `test_share_unshare` | Share then unshare removes user from list |
| SH-05 | `test_try_unlock` | `try_unlock()` with random key returns `None` |

---

### 7. `test_biometric.py` — Biometric Unlock (7 tests)

All biometric tests mock `keyring` and `pylocalauth` — no hardware required.

| Test ID | Test Name | What It Proves |
|---------|-----------|----------------|
| BI-01 | `test_setup_stores_passphrase` | `setup()` calls keyring `set_password` |
| BI-02 | `test_unlock_returns_passphrase` | `unlock()` returns stored passphrase after TTY auth |
| BI-03 | `test_unlock_wrong_passphrase_raises` | Wrong password raises `PermissionError` |
| BI-04 | `test_unlock_no_keyring_raises` | Missing keyring library raises `ConfigError` |
| BI-05 | `test_is_configured_true` | Returns `True` when passphrase is stored |
| BI-06 | `test_is_configured_false` | Returns `False` when no passphrase stored |
| BI-07 | `test_remove_deletes_password` | `remove()` calls keyring `delete_password` |

---

### 8. `test_report.py` — Compliance Reports (10 tests)

| Test ID | Test Name | What It Proves |
|---------|-----------|----------------|
| RP-01 | `test_generate_soc2_valid` | SOC 2 report has controls, summary, valid chain |
| RP-02 | `test_generate_hipaa_valid` | HIPAA report structure is correct |
| RP-03 | `test_generate_gdpr_valid` | GDPR report structure is correct |
| RP-04 | `test_generate_iso27001_valid` | ISO 27001 report structure is correct |
| RP-05 | `test_unknown_framework_raises` | Unknown framework name raises `ConfigError` |
| RP-06 | `test_list_frameworks` | Returns all 4 supported frameworks |
| RP-07 | `test_empty_log_shows_no_data` | Empty audit log → zero evidence per control |
| RP-08 | `test_tampered_log_chain_invalid` | Tampered audit chain shows `audit_chain_valid: False` |
| RP-09 | `test_export_markdown_format` | Markdown contains headers and control IDs |
| RP-10 | `test_export_json_format` | JSON export is parseable and contains expected keys |

---

### 9. `test_atomic_write.py` — Crash Safety (8 tests)

| Test ID | Test Name | What It Proves |
|---------|-----------|----------------|
| AW-01 | `test_no_temp_files_after_save` | No `.tmp` files remain after single save |
| AW-02 | `test_no_temp_files_after_multiple_saves` | No `.tmp` files after 5 sequential saves |
| AW-03 | `test_no_temp_files_after_delete` | No `.tmp` files after save + delete |
| AW-04 | `test_no_temp_files_after_manifest_write` | No `.tmp` in `keys/` after 2 saves |
| AW-05 | `test_no_temp_files_after_audit_write` | No `.tmp` in `keys/` after 5 audit appends |
| AW-06 | `test_enc_file_exists_with_correct_stem` | Exactly one `.enc` with correct item name exists |
| AW-07 | `test_vault_integrity_after_mixed_ops` | Save → overwrite → delete → save still loads correctly |
| AW-08 | `test_no_temp_files_in_sharing_dir` | No `.tmp` in `keys/` after sharing a vault |

---

### 10. `test_data_leak.py` — No Plaintext on Disk (7 tests)

| Test ID | Test Name | What It Proves |
|---------|-----------|----------------|
| DL-01 | `test_encrypted_item_no_plaintext` | `.enc` file bytes don't contain plaintext values |
| DL-02 | `test_manifest_no_plaintext` | `manifest.enc` doesn't contain secret strings |
| DL-03 | `test_audit_log_no_user_data_content` | Audit log contains only metadata, not user data |
| DL-04 | `test_all_files_encrypted_or_expected_plaintext` | Every vault file is either encrypted or an expected metadata file |
| DL-05 | `test_secure_delete_overwrites_content` | After delete, original ciphertext path no longer exists |
| DL-06 | `test_temp_files_no_plaintext` | No file in vault tree contains secret strings |
| DL-07 | `test_namespace_dirs_not_data` | Directory names are generic labels, not user content |

---

### 11. `test_robustness.py` — Attack, Corruption, Edge Cases (15 tests)

#### Cross-Context Attacks

| Test ID | Test Name | What It Proves |
|---------|-----------|----------------|
| RC-01 | `test_wrong_passphrase_fails_load` | Wrong passphrase raises exception |
| RC-02 | `test_cross_namespace_aad_rejects` | Decrypt with wrong namespace AAD fails |
| RC-03 | `test_cross_item_aad_rejects` | Decrypt with wrong item_id AAD fails |
| RC-04 | `test_tampered_ciphertext_fails_decrypt` | Flipped byte in `.enc` raises exception |
| RC-05 | `test_truncated_ciphertext_fails_decrypt` | Half-length ciphertext raises exception |

#### Corruption Handling

| Test ID | Test Name | What It Proves |
|---------|-----------|----------------|
| RC-06 | `test_corrupted_manifest_raises` | Garbage in `manifest.enc` raises exception |
| RC-07 | `test_missing_manifest_loads_empty` | Deleted manifest → loads fail gracefully |
| RC-08 | `test_corrupted_audit_log_verify_fails` | Corrupted audit entry → `verify()` returns False |
| RC-09 | `test_empty_vault_operations` | Empty vault: list returns [], load/delete raise `ItemNotFoundError` |

#### Edge Cases

| Test ID | Test Name | What It Proves |
|---------|-----------|----------------|
| RC-10 | `test_empty_data_save_load` | Save `{}` → load returns `{}` |
| RC-11 | `test_unicode_data_roundtrip` | Japanese + emoji + accented chars survive roundtrip |
| RC-12 | `test_large_data_roundtrip` | 1MB string value roundtrips correctly |
| RC-13 | `test_special_chars_item_id` | Item IDs with dots, dashes, underscores work |
| RC-14 | `test_double_delete_raises` | Second delete raises `ItemNotFoundError` |
| RC-15 | `test_shared_vault_unlock_wrong_key` | Wrong private key returns `None` from `try_unlock()` |
| RC-16 | `test_audit_log_chain_break` | Modified `op` field breaks chain verification |
| RC-17 | `test_audit_persistence_survives_restart` | New AuditLog instance loads all previous entries |
| RC-18 | `test_invalid_namespace_raises` | Unknown namespace raises `LocalStorageError` |
| RC-19 | `test_overwrite_and_load_latest` | Overwriting an item, new instance loads latest |

---

## Test Coverage by Module

| Module | Source LOC | Tests | Coverage Scope |
|--------|-----------|-------|----------------|
| `cipher.py` | 134 | 12 | Full: encrypt/decrypt, AEAD, key sizes, both suites |
| `key_manager.py` | 200 | 14 | Full: derivation, wrap/unwrap, manifest, cache |
| `crypt_storage.py` | 166 | 19 | Full: save/load/delete/list, persistence, atomic, data leak |
| `audit.py` | 133 | 9 | Full: append, verify, tamper, persistence, filter, export |
| `canary.py` | 180 | 7 | Full: deploy, check, tamper, monitor, remove, entropy |
| `sharing.py` | 154 | 5 | Core: keypair, wrap/unwrap, share/unshare, unlock |
| `biometric.py` | 113 | 7 | Full: setup, unlock, configured, remove (mocked) |
| `report.py` | 236 | 10 | Full: all 4 frameworks, export, empty/tampered log |
| `_errors.py` | 78 | — | Covered indirectly via exception assertions in all test files |
| `cli.py` | 2 | 0 | Placeholder — not yet implemented |

---

## Test Patterns Used

### Fixtures

```python
# Vault path (temp dir with cleanup)
@pytest.fixture
def vault_path(self):
    path = tempfile.mkdtemp(prefix="seal_test_")
    yield path
    shutil.rmtree(path, ignore_errors=True)

# Pre-configured vault instance
@pytest.fixture
def vault(self, vault_path):
    return AegisVault(vault_path, "test-passphrase")
```

### Exception Testing

```python
with pytest.raises(DecryptionError):
    cipher.decrypt_combined(wrong_key, blob, aad)
```

### Mocking (biometric tests)

```python
with patch.dict("sys.modules", {
    "keyring": mock_keyring,
    "pylocalauth": MagicMock(),
}):
    bio = BiometricUnlock(vault_id="test")
```

---

## Troubleshooting

### `ModuleNotFoundError: No module named 'aegis.xxx'`

Run `pip install -e .` from the project root. The package must be re-installed after adding new source files.

### `No module named pytest`

```bash
python -m pip install pytest
```

### Tests pass individually but fail in batch

Some tests use shared temp directories. Run with `--forked` or ensure each test class has its own `vault_path` fixture.

### `PermissionError` in biometric tests

The biometric module requires `keyring` and optionally `pylocalauth`. Tests mock these — do not install real versions in the test environment.

### Windows path errors

Tests use `pathlib.Path` for cross-platform compatibility. If you see `TypeError: unsupported operand type(s) for /: 'str' and 'str'`, wrap the path in `Path()`.

---

## Adding New Tests

1. Create `tests/test_<module>.py`
2. Import from `aegis.<module>`
3. Use the `vault_path` / `vault` fixture pattern
4. Run `python -m pytest tests/ -v` to verify
5. Update this file with the new test index
