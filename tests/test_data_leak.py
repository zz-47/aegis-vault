import os
import shutil
import tempfile
from pathlib import Path

import pytest
from aegis.crypt_storage import AegisVault
from aegis.audit import AuditLog


class TestDataLeak:

    @pytest.fixture
    def vault_path(self):
        path = tempfile.mkdtemp(prefix="seal_leak_test_")
        yield path
        shutil.rmtree(path, ignore_errors=True)

    @pytest.fixture
    def vault(self, vault_path):
        return AegisVault(vault_path, "test-passphrase")

    def test_encrypted_item_no_plaintext(self, vault, vault_path):
        secret = "hunter2_is_not_a_good_password"
        vault.save("personal", "doc_01", {"password": secret})
        enc_path = Path(vault_path) / "personal" / "doc_01.enc"
        raw = enc_path.read_bytes()
        assert secret.encode("utf-8") not in raw
        assert b"hunter2" not in raw

    def test_manifest_no_plaintext(self, vault, vault_path):
        secret = "super_secret_api_key_12345"
        vault.save("personal", "doc_01", {"api_key": secret})
        manifest_path = Path(vault_path) / "keys" / "manifest.enc"
        raw = manifest_path.read_bytes()
        assert secret.encode("utf-8") not in raw
        assert b"super_secret" not in raw

    def test_audit_log_no_user_data_content(self, vault, vault_path):
        log = AuditLog(vault_path)
        log.append("save", "personal", "doc_01")
        audit_path = Path(vault_path) / "keys" / "audit.log"
        raw = audit_path.read_text()
        assert "doc_01" in raw
        assert "save" in raw

    def test_all_files_encrypted_or_expected_plaintext(self, vault, vault_path):
        vault.save("personal", "doc_01", {"password": "secret123"})
        vault.save("work", "doc_02", {"api_key": "ak_abcdef"})
        for root, dirs, files in os.walk(vault_path):
            for fname in files:
                fpath = Path(root) / fname
                raw = fpath.read_bytes()
                if fname == "audit.log":
                    continue
                if fname == "canaries.json":
                    continue
                assert b"secret123" not in raw, f"Plaintext leaked in {fpath}"
                assert b"ak_abcdef" not in raw, f"Plaintext leaked in {fpath}"

    def test_secure_delete_overwrites_content(self, vault, vault_path):
        vault.save("personal", "doc_01", {"sensitive": True})
        enc_path = Path(vault_path) / "personal" / "doc_01.enc"
        original_bytes = enc_path.read_bytes()
        vault.delete("personal", "doc_01")
        assert not enc_path.exists()

    def test_temp_files_no_plaintext(self, vault, vault_path):
        secret = "leaked_plaintext_value"
        vault.save("personal", "doc_01", {"data": secret})
        for root, dirs, files in os.walk(vault_path):
            for fname in files:
                fpath = Path(root) / fname
                raw = fpath.read_bytes()
                assert secret.encode() not in raw, (
                    f"Plaintext found in {fpath}"
                )

    def test_namespace_dirs_not_data(self, vault, vault_path):
        vault.save("personal", "my_secret_note", {"text": "top secret"})
        ns_dirs = [
            d.name for d in Path(vault_path).iterdir() if d.is_dir()
        ]
        assert "keys" in ns_dirs
        assert "personal" in ns_dirs
        for ns in ns_dirs:
            assert "top secret" not in ns
            assert "my_secret_note" not in ns
