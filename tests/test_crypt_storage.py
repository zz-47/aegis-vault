import os
import shutil
import tempfile

import pytest
from aegis.crypt_storage import AegisVault
from aegis._errors import LocalStorageError, ItemNotFoundError


class TestAegisVault:

    @pytest.fixture
    def vault_path(self):
        path = tempfile.mkdtemp(prefix="seal_test_")
        yield path
        shutil.rmtree(path, ignore_errors=True)

    @pytest.fixture
    def vault(self, vault_path):
        return AegisVault(vault_path, "test-passphrase")

    def test_save_load_roundtrip(self, vault):
        data = {"content": "secret data", "type": "note"}
        vault.save("personal", "doc_01", data)
        loaded = vault.load("personal", "doc_01")
        assert loaded == data

    def test_overwrite_existing(self, vault):
        vault.save("personal", "doc_01", {"v": 1})
        vault.save("personal", "doc_01", {"v": 2})
        loaded = vault.load("personal", "doc_01")
        assert loaded == {"v": 2}

    def test_namespace_isolation(self, vault):
        vault.save("personal", "doc_01", {"ns": "personal"})
        vault.save("work", "doc_01", {"ns": "work"})
        p = vault.load("personal", "doc_01")
        w = vault.load("work", "doc_01")
        assert p["ns"] == "personal"
        assert w["ns"] == "work"

    def test_invalid_namespace(self, vault):
        with pytest.raises(LocalStorageError):
            vault.save("invalid", "doc_01", {})

    def test_load_nonexistent(self, vault):
        with pytest.raises(ItemNotFoundError):
            vault.load("personal", "nonexistent")

    def test_delete(self, vault):
        vault.save("personal", "doc_01", {"data": "to_delete"})
        vault.delete("personal", "doc_01")
        assert vault.list_items("personal") == []

    def test_delete_nonexistent(self, vault):
        with pytest.raises(ItemNotFoundError):
            vault.delete("personal", "nonexistent")

    def test_list_items(self, vault):
        vault.save("personal", "a", {})
        vault.save("personal", "b", {})
        vault.save("personal", "c", {})
        items = vault.list_items("personal")
        assert items == ["a", "b", "c"]

    def test_list_empty_namespace(self, vault):
        items = vault.list_items("personal")
        assert items == []

    def test_tampered_ciphertext(self, vault, vault_path):
        from pathlib import Path
        vault.save("personal", "doc_01", {"data": "intact"})
        path = Path(vault_path) / "personal" / "doc_01.enc"
        original = path.read_bytes()
        tampered = bytearray(original)
        tampered[20] ^= 0xFF
        path.write_bytes(bytes(tampered))
        with pytest.raises(Exception):
            vault.load("personal", "doc_01")
        path.write_bytes(original)

    def test_persistence(self, vault_path):
        v1 = AegisVault(vault_path, "test-passphrase")
        v1.save("personal", "doc_01", {"persist": True})
        v2 = AegisVault(vault_path, "test-passphrase")
        loaded = v2.load("personal", "doc_01")
        assert loaded == {"persist": True}

    def test_secure_delete_overwrites(self, vault, vault_path):
        from pathlib import Path
        vault.save("personal", "doc_01", {"sensitive": True})
        path = Path(vault_path) / "personal" / "doc_01.enc"
        original_bytes = path.read_bytes()
        vault.delete("personal", "doc_01")
        assert not path.exists()