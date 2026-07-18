import pytest
from aegis.key_manager import KeyManager
from aegis._errors import LocalStorageError, ManifestError, ItemNotFoundError


class TestKeyManager:

    def test_derive_master_key(self):
        km = KeyManager("test-passphrase")
        key = km.derive_master_key()
        assert len(key) == 32
        assert km._salt is not None

    def test_derive_with_custom_salt(self):
        import os
        salt = os.urandom(16)
        km = KeyManager("test-passphrase")
        key = km.derive_master_key(salt)
        assert len(key) == 32

    def test_invalid_salt_size(self):
        km = KeyManager("test-passphrase")
        with pytest.raises(LocalStorageError):
            km.derive_master_key(b"short")

    def test_generate_dek(self):
        km = KeyManager("test-passphrase")
        dek = km.generate_dek()
        assert len(dek) == 32

    def test_wrap_unwrap_roundtrip(self):
        km = KeyManager("test-passphrase")
        km.derive_master_key()
        dek = km.generate_dek()
        wrapped = km.wrap_dek(dek, b"item_01")
        unwrapped = km.unwrap_dek(wrapped, b"item_01")
        assert unwrapped == dek

    def test_wrong_item_id_fails(self):
        km = KeyManager("test-passphrase")
        km.derive_master_key()
        dek = km.generate_dek()
        wrapped = km.wrap_dek(dek, b"item_01")
        with pytest.raises(LocalStorageError):
            km.unwrap_dek(wrapped, b"wrong_id")

    def test_wrap_without_master_key(self):
        km = KeyManager("test-passphrase")
        with pytest.raises(LocalStorageError):
            km.wrap_dek(b"0" * 32, b"item")

    def test_export_import_manifest_roundtrip(self):
        km = KeyManager("test-passphrase")
        km.derive_master_key()
        manifest = {"version": 1, "items": {}}
        blob = km.export_encrypted_manifest(manifest)
        km2 = KeyManager("test-passphrase")
        loaded = km2.import_encrypted_manifest(blob)
        assert loaded == manifest

    def test_import_wrong_passphrase(self):
        km = KeyManager("correct-passphrase")
        km.derive_master_key()
        blob = km.export_encrypted_manifest({"version": 1, "items": {}})
        km2 = KeyManager("wrong-passphrase")
        with pytest.raises(Exception):
            km2.import_encrypted_manifest(blob)

    def test_import_truncated_blob(self):
        km = KeyManager("test-passphrase")
        with pytest.raises(ManifestError):
            km.import_encrypted_manifest(b"short")

    def test_get_dek_from_manifest(self):
        km = KeyManager("test-passphrase")
        km.derive_master_key()
        dek = km.generate_dek()
        wrapped = km.wrap_dek(dek, b"item_01")
        manifest = {
            "version": 1,
            "items": {
                "item_01": {"dek": wrapped, "namespace": "personal"},
            },
        }
        retrieved = km.get_dek("item_01", manifest)
        assert retrieved == dek

    def test_get_dek_missing_item(self):
        km = KeyManager("test-passphrase")
        km.derive_master_key()
        manifest = {"version": 1, "items": {}}
        with pytest.raises(ItemNotFoundError):
            km.get_dek("nonexistent", manifest)

    def test_dek_cache(self):
        km = KeyManager("test-passphrase")
        km.derive_master_key()
        km.cache_dek(b"item_01", b"cached_dek_32bytes___________")
        cached = km.get_cached_dek(b"item_01")
        assert cached == b"cached_dek_32bytes___________"

    def test_cache_fifo_eviction(self):
        km = KeyManager("test", overrides={"max_cached_deks": 2})
        km.cache_dek(b"a", b"1" * 32)
        km.cache_dek(b"b", b"2" * 32)
        km.cache_dek(b"c", b"3" * 32)
        assert km.get_cached_dek(b"a") is None
        assert km.get_cached_dek(b"c") is not None