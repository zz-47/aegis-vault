import json
import shutil
import tempfile
from pathlib import Path

import pytest
from aegis.audit import AuditLog
from aegis.report import ComplianceReport
from aegis._errors import ConfigError


class TestComplianceReport:

    @pytest.fixture
    def vault_path(self):
        path = tempfile.mkdtemp(prefix="seal_report_test_")
        yield path
        shutil.rmtree(path, ignore_errors=True)

    @pytest.fixture
    def log_with_entries(self, vault_path):
        log = AuditLog(vault_path)
        log.append("save", "personal", "doc_01")
        log.append("load", "personal", "doc_01")
        log.append("delete", "personal", "doc_01")
        return log

    @pytest.fixture
    def empty_log(self, vault_path):
        return AuditLog(vault_path)

    def test_generate_soc2_valid(self, log_with_entries):
        report = ComplianceReport(log_with_entries)
        result = report.generate("soc2")
        assert "controls" in result
        assert "summary" in result
        assert result["audit_chain_valid"] is True
        assert result["framework"] == "SOC 2 Type II"

    def test_generate_hipaa_valid(self, log_with_entries):
        report = ComplianceReport(log_with_entries)
        result = report.generate("hipaa")
        assert "controls" in result
        assert result["framework"] == "HIPAA Security Rule"
        assert result["summary"]["total_controls"] > 0

    def test_generate_gdpr_valid(self, log_with_entries):
        report = ComplianceReport(log_with_entries)
        result = report.generate("gdpr")
        assert "controls" in result
        assert result["framework"] == "GDPR (General Data Protection Regulation)"

    def test_generate_iso27001_valid(self, log_with_entries):
        report = ComplianceReport(log_with_entries)
        result = report.generate("iso27001")
        assert "controls" in result
        assert result["framework"] == "ISO/IEC 27001:2022"

    def test_unknown_framework_raises(self, log_with_entries):
        report = ComplianceReport(log_with_entries)
        with pytest.raises(ConfigError):
            report.generate("bogus_framework")

    def test_list_frameworks(self, log_with_entries):
        report = ComplianceReport(log_with_entries)
        frameworks = report.list_frameworks()
        assert set(frameworks) == {"soc2", "hipaa", "gdpr", "iso27001"}

    def test_empty_log_shows_no_data(self, empty_log):
        report = ComplianceReport(empty_log)
        result = report.generate("soc2")
        for ctrl_id, ctrl in result["controls"].items():
            assert ctrl["evidence_count"] == 0
            assert ctrl["sample_operations"] == []

    def test_tampered_log_chain_invalid(self, vault_path):
        log = AuditLog(vault_path)
        log.append("save", "personal", "doc_01")
        log._entries[0].op = "delete"
        report = ComplianceReport(log)
        result = report.generate("soc2")
        assert result["audit_chain_valid"] is False

    def test_export_markdown_format(self, log_with_entries):
        report = ComplianceReport(log_with_entries)
        md = report.export_markdown("soc2")
        assert "# SOC 2 Type II Compliance Report" in md
        assert "**Audit Chain:** VALID" in md
        assert "CC6.1" in md
        assert "CC6.6" in md

    def test_export_json_format(self, log_with_entries):
        report = ComplianceReport(log_with_entries)
        raw = report.export_json("soc2")
        parsed = json.loads(raw)
        assert "controls" in parsed
        assert "summary" in parsed
        assert "generated_at" in parsed
