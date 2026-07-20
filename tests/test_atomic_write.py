import shutil
import tempfile
from pathlib import Path

import pytest
from aegis.crypt_storage import AegisVault
from aegis.audit import AuditLog
from aegis.sharing import ShareManager


class TestAtomicWrite:

    @pytest.fixture
    def vault_path(self):
        path = tempfile.mkdtemp(prefix="seal_atomic_test_")
        yield path
        shutil.rmtree(path, ignore_errors=True)

    @pytest.fixture
    def vault(self, vault_path):
        return AegisVault(vault_path, "test-passphrase")

    def test_no_temp_files_after_save(self, vault, vault_path):
        vault.save("personal", "doc_01", {"data": "secret"})
        tmp_files = list(Path(vault_path).rglob("*.tmp"))
        assert tmp_files == []

    def test_no_temp_files_after_multiple_saves(self, vault, vault_path):
        for i in range(5):
            vault.save("personal", f"doc_{i:02d}", {"idx": i})
        tmp_files = list(Path(vault_path).rglob("*.tmp"))
        assert tmp_files == []

    def test_no_temp_files_after_delete(self, vault, vault_path):
        vault.save("personal", "doc_01", {"data": "to_delete"})
        vault.delete("personal", "doc_01")
        tmp_files = list(Path(vault_path).rglob("*.tmp"))
        assert tmp_files == []

    def test_no_temp_files_after_manifest_write(self, vault, vault_path):
        vault.save("personal", "doc_01", {"data": "a"})
        vault.save("personal", "doc_02", {"data": "b"})
        keys_dir = Path(vault_path) / "keys"
        tmp_files = list(keys_dir.rglob("*.tmp"))
        assert tmp_files == []

    def test_no_temp_files_after_audit_write(self, vault_path):
        log = AuditLog(vault_path)
        for i in range(5):
            log.append("save", "personal", f"doc_{i:02d}")
        keys_dir = Path(vault_path) / "keys"
        tmp_files = list(keys_dir.rglob("*.tmp"))
        assert tmp_files == []

    def test_enc_file_exists_with_correct_stem(self, vault, vault_path):
        vault.save("personal", "doc_01", {"data": "test"})
        ns_dir = Path(vault_path) / "personal"
        enc_files = list(ns_dir.glob("*.enc"))
        tmp_files = list(ns_dir.glob("*.tmp"))
        assert len(enc_files) == 1
        assert enc_files[0].stem == "doc_01"
        assert tmp_files == []

    def test_vault_integrity_after_mixed_ops(self, vault):
        vault.save("personal", "doc_01", {"v": 1})
        vault.save("personal", "doc_01", {"v": 2})
        vault.delete("personal", "doc_01")
        vault.save("personal", "doc_02", {"v": 3})
        loaded = vault.load("personal", "doc_02")
        assert loaded == {"v": 3}
        items = vault.list_items("personal")
        assert items == ["doc_02"]

    def test_no_temp_files_in_sharing_dir(self, vault_path):
        sm = ShareManager(vault_path)
        user_id, pub_hex, _priv = sm.generate_keypair()
        dek = b"\x00" * 32
        sm.share_vault(user_id, pub_hex, dek)
        keys_dir = Path(vault_path) / "keys"
        tmp_files = list(keys_dir.rglob("*.tmp"))
        assert tmp_files == []
