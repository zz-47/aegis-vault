import os
import shutil
import tempfile
from pathlib import Path

import pytest
from aegis.crypt_storage import AegisVault
from aegis.audit import AuditLog
from aegis._errors import (
    DecryptionError,
    ItemNotFoundError,
    ManifestError,
    LocalStorageError,
)
from aegis.sharing import ShareManager, _wrap_dek_for_user, _unwrap_dek_from_stanza
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


class TestCrossContextAttacks:

    @pytest.fixture
    def vault_path(self):
        path = tempfile.mkdtemp(prefix="seal_robust_test_")
        yield path
        shutil.rmtree(path, ignore_errors=True)

    def test_wrong_passphrase_fails_load(self, vault_path):
        v1 = AegisVault(vault_path, "correct-passphrase")
        v1.save("personal", "doc_01", {"data": "secret"})
        with pytest.raises(Exception):
            AegisVault(vault_path, "wrong-passphrase")

    def test_cross_namespace_aad_rejects(self, vault_path):
        v1 = AegisVault(vault_path, "pass")
        v1.save("personal", "doc_01", {"data": "secret"})
        from aegis.key_manager import KeyManager
        from aegis.cipher import AeadCipher
        cipher = AeadCipher()
        key = os.urandom(32)
        aad_wrong = b"aegis_ns:work:doc_01"
        blob = Path(vault_path) / "personal" / "doc_01.enc"
        raw = blob.read_bytes()
        dek = v1._km.get_dek("doc_01", v1._manifest)
        with pytest.raises(DecryptionError):
            cipher.decrypt_combined(dek, raw, aad_wrong)

    def test_cross_item_aad_rejects(self, vault_path):
        v1 = AegisVault(vault_path, "pass")
        v1.save("personal", "doc_01", {"data": "secret"})
        blob = Path(vault_path) / "personal" / "doc_01.enc"
        raw = blob.read_bytes()
        dek = v1._km.get_dek("doc_01", v1._manifest)
        aad_wrong = b"aegis_ns:personal:doc_99"
        from aegis.cipher import AeadCipher
        cipher = AeadCipher()
        with pytest.raises(DecryptionError):
            cipher.decrypt_combined(dek, raw, aad_wrong)

    def test_tampered_ciphertext_fails_decrypt(self, vault_path):
        v1 = AegisVault(vault_path, "pass")
        v1.save("personal", "doc_01", {"data": "intact"})
        enc_path = Path(vault_path) / "personal" / "doc_01.enc"
        raw = bytearray(enc_path.read_bytes())
        raw[10] ^= 0xFF
        enc_path.write_bytes(bytes(raw))
        with pytest.raises(Exception):
            v1.load("personal", "doc_01")

    def test_truncated_ciphertext_fails_decrypt(self, vault_path):
        v1 = AegisVault(vault_path, "pass")
        v1.save("personal", "doc_01", {"data": "full"})
        enc_path = Path(vault_path) / "personal" / "doc_01.enc"
        raw = enc_path.read_bytes()
        enc_path.write_bytes(raw[:len(raw) // 2])
        with pytest.raises(Exception):
            v1.load("personal", "doc_01")


class TestCorruptionHandling:

    @pytest.fixture
    def vault_path(self):
        path = tempfile.mkdtemp(prefix="seal_corrupt_test_")
        yield path
        shutil.rmtree(path, ignore_errors=True)

    def test_corrupted_manifest_raises(self, vault_path):
        v1 = AegisVault(vault_path, "pass")
        v1.save("personal", "doc_01", {"data": "ok"})
        manifest_path = Path(vault_path) / "keys" / "manifest.enc"
        manifest_path.write_bytes(os.urandom(256))
        with pytest.raises(Exception):
            AegisVault(vault_path, "pass")

    def test_missing_manifest_loads_empty(self, vault_path):
        v1 = AegisVault(vault_path, "pass")
        v1.save("personal", "doc_01", {"data": "before"})
        manifest_path = Path(vault_path) / "keys" / "manifest.enc"
        assert manifest_path.exists()
        manifest_path.unlink()
        v2 = AegisVault(vault_path, "pass")
        with pytest.raises(Exception):
            v2.load("personal", "doc_01")

    def test_corrupted_audit_log_verify_fails(self, vault_path):
        log = AuditLog(vault_path)
        log.append("save", "personal", "doc_01")
        audit_path = Path(vault_path) / "keys" / "audit.log"
        lines = audit_path.read_text().splitlines()
        lines[0] = lines[0].replace('"op":"save"', '"op":"delete"')
        audit_path.write_text("\n".join(lines))
        log2 = AuditLog(vault_path)
        assert log2.verify() is False

    def test_empty_vault_operations(self, vault_path):
        v1 = AegisVault(vault_path, "pass")
        assert v1.list_items("personal") == []
        assert v1.list_items("work") == []
        with pytest.raises(ItemNotFoundError):
            v1.load("personal", "nonexistent")
        with pytest.raises(ItemNotFoundError):
            v1.delete("personal", "nonexistent")


class TestEdgeCases:

    @pytest.fixture
    def vault_path(self):
        path = tempfile.mkdtemp(prefix="seal_edge_test_")
        yield path
        shutil.rmtree(path, ignore_errors=True)

    def test_empty_data_save_load(self, vault_path):
        v1 = AegisVault(vault_path, "pass")
        v1.save("personal", "empty", {})
        v2 = AegisVault(vault_path, "pass")
        assert v2.load("personal", "empty") == {}

    def test_unicode_data_roundtrip(self, vault_path):
        data = {"text": "日本語テスト 🔥 émojis & spëcial chars"}
        v1 = AegisVault(vault_path, "pass")
        v1.save("personal", "unicode_doc", data)
        v2 = AegisVault(vault_path, "pass")
        loaded = v2.load("personal", "unicode_doc")
        assert loaded == data

    def test_large_data_roundtrip(self, vault_path):
        data = {"blob": "x" * 1_000_000}
        v1 = AegisVault(vault_path, "pass")
        v1.save("personal", "large_doc", data)
        v2 = AegisVault(vault_path, "pass")
        loaded = v2.load("personal", "large_doc")
        assert loaded == data

    def test_special_chars_item_id(self, vault_path):
        v1 = AegisVault(vault_path, "pass")
        item_id = "my-doc_v2.1"
        v1.save("personal", item_id, {"data": "special"})
        v2 = AegisVault(vault_path, "pass")
        assert v2.load("personal", item_id) == {"data": "special"}

    def test_double_delete_raises(self, vault_path):
        v1 = AegisVault(vault_path, "pass")
        v1.save("personal", "doc_01", {"data": "once"})
        v1.delete("personal", "doc_01")
        with pytest.raises(ItemNotFoundError):
            v1.delete("personal", "doc_01")

    def test_shared_vault_unlock_wrong_key(self, vault_path):
        sm = ShareManager(vault_path)
        user_id, pub_hex, _priv = sm.generate_keypair()
        dek = os.urandom(32)
        sm.share_vault(user_id, pub_hex, dek)
        wrong_priv = X25519PrivateKey.generate()
        wrong_priv_hex = wrong_priv.private_bytes_raw().hex()
        result = sm.try_unlock(wrong_priv_hex)
        assert result is None

    def test_audit_log_chain_break(self, vault_path):
        log = AuditLog(vault_path)
        log.append("save", "personal", "doc_01")
        log.append("load", "personal", "doc_01")
        log.append("delete", "personal", "doc_01")
        log._entries[1].op = "delete"
        assert log.verify() is False

    def test_audit_persistence_survives_restart(self, vault_path):
        log1 = AuditLog(vault_path)
        log1.append("save", "personal", "doc_01")
        log1.append("load", "personal", "doc_01")
        log2 = AuditLog(vault_path)
        assert log2.entry_count == 2
        assert log2.verify()

    def test_invalid_namespace_raises(self, vault_path):
        v1 = AegisVault(vault_path, "pass")
        with pytest.raises(LocalStorageError):
            v1.save("invalid_namespace", "doc_01", {})

    def test_overwrite_and_load_latest(self, vault_path):
        v1 = AegisVault(vault_path, "pass")
        v1.save("personal", "doc_01", {"version": 1})
        v1.save("personal", "doc_01", {"version": 2})
        v2 = AegisVault(vault_path, "pass")
        assert v2.load("personal", "doc_01") == {"version": 2}
