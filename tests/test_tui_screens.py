from __future__ import annotations

import json
import math
import string
import tempfile
from pathlib import Path

import pytest
from textual.app import ComposeResult
from textual.widgets import DataTable, Static, Label, Select

from aegis.crypt_storage import AegisVault


PASSWORD = "correct-horse-battery-staple"


@pytest.fixture()
def vault_path(tmp_path):
    v = AegisVault(tmp_path, PASSWORD)
    v.save("personal", "gmail", {"user": "a@b.com", "pass": "x"})
    v.save("personal", "github", {"user": "dev", "pass": "y"})
    v.save("work", "wifi", {"ssid": "HomeNet", "pass": "secret"})
    return tmp_path


class TestGeneratorScreen:
    def test_compose(self):
        from aegis.tui.screens.generator import GeneratorScreen

        screen = GeneratorScreen()
        assert screen.length == 24

    def test_generate_length(self):
        from aegis.tui.screens.generator import GeneratorScreen

        screen = GeneratorScreen(length=32)
        pw = screen._generate()
        assert len(pw) == 32

    def test_generate_uses_alphabet(self):
        from aegis.tui.screens.generator import GeneratorScreen

        screen = GeneratorScreen()
        pw = screen._generate()
        allowed = set(string.ascii_letters + string.digits + screen._alphabet())
        assert all(ch in allowed for ch in pw)

    def test_strength_label_weak(self):
        from aegis.tui.screens.generator import GeneratorScreen

        screen = GeneratorScreen(length=4)
        label = screen._strength_label(4)
        assert "WEAK" in label

    def test_strength_label_strong(self):
        from aegis.tui.screens.generator import GeneratorScreen

        screen = GeneratorScreen(length=32)
        label = screen._strength_label(32)
        assert "STRONG" in label or "VERY STRONG" in label

    def test_entropy_calculation(self):
        from aegis.tui.screens.generator import GeneratorScreen

        screen = GeneratorScreen()
        alphabet_size = len(screen._alphabet())
        expected = 24 * math.log2(alphabet_size)
        assert expected > 100


class TestCanaryScreen:
    def test_import(self):
        from aegis.tui.screens.canary import CanaryScreen

        assert CanaryScreen is not None

    def test_canary_manager_deploy_and_check(self, vault_path):
        from aegis.canary import CanaryManager

        mgr = CanaryManager(vault_path)
        new = mgr.deploy(["test_canary.txt"])
        assert len(new) > 0
        result = mgr.check_all()
        assert result.is_clean is True

    def test_canary_triggered_on_modify(self, vault_path):
        from aegis.canary import CanaryManager

        mgr = CanaryManager(vault_path)
        new = mgr.deploy(["test_canary.txt"])
        assert len(new) > 0
        for cf in new:
            p = Path(cf.path)
            p.write_bytes(b"modified content that is very different")
        result = mgr.check_all()
        assert result.is_clean is False
        assert len(result.triggered) > 0

    def test_canary_remove(self, vault_path):
        from aegis.canary import CanaryManager

        mgr = CanaryManager(vault_path)
        mgr.deploy(["test_canary.txt"])
        count = mgr.remove()
        assert count > 0
        assert mgr.status() == []


class TestReportScreen:
    def test_import(self):
        from aegis.tui.screens.report import ReportScreen

        assert ReportScreen is not None

    def test_report_generate(self, vault_path):
        from aegis.audit import AuditLog
        from aegis.report import ComplianceReport

        audit = AuditLog(vault_path)
        report = ComplianceReport(audit)
        for fw in ["soc2", "hipaa", "gdpr", "iso27001"]:
            data = report.generate(fw)
            assert data["framework"]
            assert "controls" in data
            assert data["summary"]["total_controls"] > 0

    def test_report_markdown_export(self, vault_path):
        from aegis.audit import AuditLog
        from aegis.report import ComplianceReport

        audit = AuditLog(vault_path)
        report = ComplianceReport(audit)
        md = report.export_markdown("soc2")
        assert "# SOC 2" in md
        assert "Compliant" in md or "COMPLIANT" in md or "NO_DATA" in md


class TestVaultPickerScreen:
    def test_import(self):
        from aegis.tui.screens.picker import VaultPickerScreen

        assert VaultPickerScreen is not None

    def test_count_entries(self, vault_path):
        from aegis.tui.screens.picker import VaultPickerScreen

        screen = VaultPickerScreen()
        count = screen._count_entries(vault_path)
        assert count == 3

    def test_check_audit(self, vault_path):
        from aegis.tui.screens.picker import VaultPickerScreen

        screen = VaultPickerScreen()
        ok = screen._check_audit(vault_path)
        assert ok is True


class TestAppBindings:
    def test_app_import(self):
        from aegis.tui.app import SealApp

        assert SealApp is not None

    def test_app_has_new_bindings(self):
        from aegis.tui.app import SealApp

        keys = [b.key for b in SealApp.BINDINGS]
        assert "ctrl+r" in keys
        assert "ctrl+y" in keys
        assert "ctrl+o" in keys

    def test_screen_exports(self):
        from aegis.tui.screens import (
            CanaryScreen,
            ReportScreen,
            VaultPickerScreen,
        )

        assert CanaryScreen is not None
        assert ReportScreen is not None
        assert VaultPickerScreen is not None

    def test_tui_exports(self):
        from aegis.tui import (
            CanaryScreen,
            ReportScreen,
            VaultPickerScreen,
        )

        assert CanaryScreen is not None
        assert ReportScreen is not None
        assert VaultPickerScreen is not None
