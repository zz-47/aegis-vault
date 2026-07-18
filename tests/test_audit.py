import os
import shutil
import tempfile

import pytest
from aegis.audit import AuditLog


class TestAuditLog:

    @pytest.fixture
    def vault_path(self):
        path = tempfile.mkdtemp(prefix="seal_audit_test_")
        yield path
        shutil.rmtree(path, ignore_errors=True)

    def test_append_and_verify(self, vault_path):
        log = AuditLog(vault_path)
        log.append("save", "personal", "doc_01")
        log.append("load", "personal", "doc_01")
        assert log.verify()
        assert log.entry_count == 2

    def test_verify_empty_log(self, vault_path):
        log = AuditLog(vault_path)
        assert log.verify()

    def test_tamper_detection(self, vault_path):
        log = AuditLog(vault_path)
        log.append("save", "personal", "doc_01")
        log._entries[0].op = "delete"
        assert not log.verify()

    def test_persistence(self, vault_path):
        log1 = AuditLog(vault_path)
        log1.append("save", "personal", "doc_01")
        log2 = AuditLog(vault_path)
        assert log2.entry_count == 1
        assert log2.verify()

    def test_filter_by_namespace(self, vault_path):
        log = AuditLog(vault_path)
        log.append("save", "personal", "doc_01")
        log.append("save", "work", "doc_02")
        log.append("load", "personal", "doc_01")
        results = log.get_entries(namespace="personal")
        assert len(results) == 2

    def test_filter_by_op(self, vault_path):
        log = AuditLog(vault_path)
        log.append("save", "personal", "doc_01")
        log.append("load", "personal", "doc_01")
        log.append("delete", "personal", "doc_01")
        results = log.get_entries(op="save")
        assert len(results) == 1

    def test_export_json(self, vault_path):
        log = AuditLog(vault_path)
        log.append("save", "personal", "doc_01")
        export = log.export_json()
        assert '"op":"save"' in export