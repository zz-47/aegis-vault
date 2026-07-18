import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from aegis.cli import cli
from aegis.crypt_storage import AegisVault


PASSPHRASE = "test-passphrase-123"


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def vault_path(tmp_path):
    path = tmp_path / "vault"
    path.mkdir()
    AegisVault(str(path), PASSPHRASE)
    return str(path)


def _vault_args(vp):
    return ["--path", vp, "--passphrase", PASSPHRASE]


def _save_item(vp, ns="personal", item_id="doc1", data=None):
    v = AegisVault(vp, PASSPHRASE)
    v.save(ns, item_id, data or {"key": "value"})


class TestCLIVersion:

    def test_version(self, runner):
        result = runner.invoke(cli, ["version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output


class TestCLIHelp:

    def test_help_shows_all_commands(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        for cmd in ["init", "save", "load", "list", "delete", "verify",
                     "canary", "report", "share", "tui", "gui", "version"]:
            assert cmd in result.output


class TestCLIInit:

    def test_init_creates_vault(self, runner):
        with runner.isolated_filesystem():
            result = runner.invoke(cli, [
                "init", "--path", "./test-vault", "--passphrase", PASSPHRASE,
            ])
            assert result.exit_code == 0
            assert Path("./test-vault").exists()
            assert Path("./test-vault/keys").exists()

    def test_init_chacha20(self, runner):
        with runner.isolated_filesystem():
            result = runner.invoke(cli, [
                "init", "--path", "./test-vault", "--passphrase", PASSPHRASE,
                "--cipher", "chacha20",
            ])
            assert result.exit_code == 0
            assert Path("./test-vault/keys").exists()


class TestCLISave:

    def test_save_json_data(self, runner, vault_path):
        args = _vault_args(vault_path) + [
            "save", "-n", "personal", "-i", "doc1",
            "-d", '{"user":"alice","password":"s3cret"}',
        ]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        assert "Saved" in result.output
        assert Path(vault_path, "personal", "doc1.enc").exists()

    def test_save_from_file(self, runner, vault_path, tmp_path):
        json_file = tmp_path / "input.json"
        json_file.write_text('{"api_key":"from-file"}')
        args = _vault_args(vault_path) + [
            "save", "-n", "work", "-i", "config",
            "-f", str(json_file),
        ]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        assert "Saved" in result.output
        assert Path(vault_path, "work", "config.enc").exists()

    def test_save_invalid_namespace(self, runner, vault_path):
        args = _vault_args(vault_path) + [
            "save", "-n", "bogus", "-i", "doc1", "-d", '{"x":1}',
        ]
        result = runner.invoke(cli, args)
        assert result.exit_code != 0


class TestCLILoad:

    def test_load_json_output(self, runner, vault_path):
        _save_item(vault_path, data={"user": "bob", "token": "abc"})
        args = _vault_args(vault_path) + [
            "load", "-n", "personal", "-i", "doc1", "-F", "json",
        ]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["user"] == "bob"
        assert parsed["token"] == "abc"

    def test_load_text_format(self, runner, vault_path):
        _save_item(vault_path, data={"key": "val"})
        args = _vault_args(vault_path) + [
            "load", "-n", "personal", "-i", "doc1", "-F", "text",
        ]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        assert "key" in result.output

    def test_load_missing_item(self, runner, vault_path):
        args = _vault_args(vault_path) + [
            "load", "-n", "personal", "-i", "nonexistent",
        ]
        result = runner.invoke(cli, args)
        assert result.exit_code != 0


class TestCLIList:

    def test_list_empty_vault(self, runner, vault_path):
        args = _vault_args(vault_path) + ["list"]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        assert "(empty)" in result.output

    def test_list_with_items(self, runner, vault_path):
        _save_item(vault_path, item_id="login1")
        _save_item(vault_path, item_id="login2", data={"x": 1})
        args = _vault_args(vault_path) + ["list", "-n", "personal"]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        assert "login1" in result.output
        assert "login2" in result.output

    def test_list_namespace_filter(self, runner, vault_path):
        _save_item(vault_path, ns="personal", item_id="p1")
        _save_item(vault_path, ns="work", item_id="w1", data={"x": 1})
        args = _vault_args(vault_path) + ["list", "-n", "work"]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        assert "w1" in result.output
        assert "p1" not in result.output

    def test_list_all_namespaces(self, runner, vault_path):
        _save_item(vault_path, ns="personal", item_id="p1")
        _save_item(vault_path, ns="work", item_id="w1", data={"x": 1})
        args = _vault_args(vault_path) + ["list"]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        assert "personal/" in result.output
        assert "work/" in result.output

    def test_list_json_format(self, runner, vault_path):
        _save_item(vault_path, item_id="j1")
        args = _vault_args(vault_path) + ["list", "-F", "json"]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert "personal" in parsed
        assert "j1" in parsed["personal"]


class TestCLIDelete:

    def test_delete_with_yes_flag(self, runner, vault_path):
        _save_item(vault_path, item_id="to_delete")
        assert Path(vault_path, "personal", "to_delete.enc").exists()
        args = _vault_args(vault_path) + [
            "delete", "-n", "personal", "-i", "to_delete", "-y",
        ]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        assert "Deleted" in result.output
        assert not Path(vault_path, "personal", "to_delete.enc").exists()

    def test_delete_aborts_without_flag(self, runner, vault_path):
        _save_item(vault_path, item_id="keep_me")
        args = _vault_args(vault_path) + [
            "delete", "-n", "personal", "-i", "keep_me",
        ]
        result = runner.invoke(cli, args, input="n\n")
        assert result.exit_code != 0 or "Deleted" not in result.output
        assert Path(vault_path, "personal", "keep_me.enc").exists()

    def test_delete_missing_item(self, runner, vault_path):
        args = _vault_args(vault_path) + [
            "delete", "-n", "personal", "-i", "nope", "-y",
        ]
        result = runner.invoke(cli, args)
        assert result.exit_code != 0


class TestCLIVerify:

    def test_verify_clean(self, runner, vault_path):
        _save_item(vault_path)
        args = _vault_args(vault_path) + ["verify"]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        assert "VALID" in result.output

    def test_verify_json_output(self, runner, vault_path):
        _save_item(vault_path)
        args = _vault_args(vault_path) + ["verify", "-F", "json"]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["audit_chain"] == "valid"
        assert parsed["audit_entries"] >= 0
        assert "timestamp" in parsed

    def test_verify_broken_chain(self, runner, vault_path):
        _save_item(vault_path)
        from aegis.audit import AuditLog
        log = AuditLog(vault_path)
        log.append("load", "personal", "doc1")
        log.append("save", "personal", "doc1")
        log._entries[0].op = "tampered"
        log._persist()
        args = _vault_args(vault_path) + ["verify", "-F", "json"]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["audit_chain"] == "broken"


class TestCLICanary:

    def test_canary_deploy(self, runner, vault_path):
        args = _vault_args(vault_path) + ["canary", "deploy"]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        assert "Deployed" in result.output

    def test_canary_deploy_custom_names(self, runner, vault_path):
        args = _vault_args(vault_path) + [
            "canary", "deploy", "--names", "fake.xlsx,fake.pdf",
        ]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0

    def test_canary_check_clean(self, runner, vault_path):
        runner.invoke(cli, _vault_args(vault_path) + ["canary", "deploy"])
        args = _vault_args(vault_path) + ["canary", "check"]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        assert "intact" in result.output.lower()

    def test_canary_check_tampered(self, runner, vault_path):
        runner.invoke(cli, _vault_args(vault_path) + ["canary", "deploy"])
        from aegis.canary import CanaryManager
        mgr = CanaryManager(vault_path)
        assert len(mgr._canaries) > 0
        first = mgr._canaries[0]
        with open(first.path, "wb") as f:
            f.write(os.urandom(1024))
        args = _vault_args(vault_path) + ["canary", "check"]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        assert "TRIGGERED" in result.output

    def test_canary_remove(self, runner, vault_path):
        runner.invoke(cli, _vault_args(vault_path) + ["canary", "deploy"])
        args = _vault_args(vault_path) + ["canary", "remove"]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        assert "Removed" in result.output


class TestCLIReport:

    def test_report_generate_soc2(self, runner, vault_path):
        _save_item(vault_path)
        args = _vault_args(vault_path) + ["report", "generate", "-f", "soc2"]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        assert "SOC 2" in result.output
        assert "CC6." in result.output

    def test_report_generate_hipaa(self, runner, vault_path):
        _save_item(vault_path)
        args = _vault_args(vault_path) + ["report", "generate", "-f", "hipaa"]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        assert "HIPAA" in result.output

    def test_report_json_output(self, runner, vault_path):
        _save_item(vault_path)
        args = _vault_args(vault_path) + [
            "report", "generate", "-f", "gdpr", "-F", "json",
        ]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert "controls" in parsed
        assert "summary" in parsed

    def test_report_markdown_output(self, runner, vault_path):
        _save_item(vault_path)
        args = _vault_args(vault_path) + [
            "report", "generate", "-f", "iso27001", "-F", "markdown",
        ]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        assert "#" in result.output

    def test_report_unknown_framework(self, runner, vault_path):
        _save_item(vault_path)
        args = _vault_args(vault_path) + [
            "report", "generate", "-f", "bogus",
        ]
        result = runner.invoke(cli, args)
        assert result.exit_code != 0


class TestCLIShare:

    def _keypair(self):
        priv = X25519PrivateKey.generate()
        pub_hex = priv.public_key().public_bytes_raw().hex()
        return pub_hex

    def test_share_add(self, runner, vault_path):
        pub = self._keypair()
        dek_hex = os.urandom(32).hex()
        args = _vault_args(vault_path) + [
            "share", "add", "-u", pub, "-d", dek_hex,
        ]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        assert "added" in result.output.lower()

    def test_share_list_empty(self, runner, vault_path):
        args = _vault_args(vault_path) + ["share", "list"]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        assert "No users" in result.output or "(empty)" in result.output or result.output.strip() == ""

    def test_share_list_with_users(self, runner, vault_path):
        pub = self._keypair()
        dek_hex = os.urandom(32).hex()
        runner.invoke(cli, _vault_args(vault_path) + [
            "share", "add", "-u", pub, "-d", dek_hex,
        ])
        args = _vault_args(vault_path) + ["share", "list"]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        assert "user" in result.output

    def test_share_remove(self, runner, vault_path):
        pub = self._keypair()
        dek_hex = os.urandom(32).hex()
        runner.invoke(cli, _vault_args(vault_path) + [
            "share", "add", "-u", pub, "-d", dek_hex,
        ])
        args = _vault_args(vault_path) + ["share", "remove", "-u", pub]
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        assert "removed" in result.output.lower()

    def test_share_invalid_pubkey_length(self, runner, vault_path):
        short_key = "aa" * 16
        dek_hex = os.urandom(32).hex()
        args = _vault_args(vault_path) + [
            "share", "add", "-u", short_key, "-d", dek_hex,
        ]
        result = runner.invoke(cli, args)
        assert result.exit_code != 0
