import os
import shutil
import tempfile
from pathlib import Path

import pytest
from aegis.canary import CanaryManager, CanaryCheckResult, _shannon_entropy


class TestCanaryManager:

    @pytest.fixture
    def vault_path(self):
        path = tempfile.mkdtemp(prefix="seal_canary_test_")
        yield path
        shutil.rmtree(path, ignore_errors=True)

    def test_deploy_creates_files(self, vault_path):
        mgr = CanaryManager(vault_path, watch_dirs=[vault_path])
        canaries = mgr.deploy(names=["test_canary.txt"])
        assert len(canaries) > 0
        assert os.path.exists(canaries[0].path)

    def test_check_intact(self, vault_path):
        mgr = CanaryManager(vault_path, watch_dirs=[vault_path])
        mgr.deploy(names=["test_canary.txt"])
        result = mgr.check_all()
        assert result.is_clean is True
        assert len(result.triggered) == 0
        assert len(result.missing) == 0

    def test_tamper_detection(self, vault_path):
        mgr = CanaryManager(vault_path, watch_dirs=[vault_path])
        canaries = mgr.deploy(names=["test_canary.txt"])
        with open(canaries[0].path, "wb") as f:
            f.write(os.urandom(1024))
        result = mgr.check_all()
        assert result.is_clean is False
        assert len(result.triggered) > 0

    def test_monitor_once_raises(self, vault_path):
        mgr = CanaryManager(vault_path, watch_dirs=[vault_path])
        canaries = mgr.deploy(names=["test_canary.txt"])
        with open(canaries[0].path, "wb") as f:
            f.write(os.urandom(1024))
        from aegis._errors import PermissionError
        with pytest.raises(PermissionError):
            mgr.monitor_once()

    def test_remove_canaries(self, vault_path):
        mgr = CanaryManager(vault_path, watch_dirs=[vault_path])
        canaries = mgr.deploy(names=["test_canary.txt"])
        path = canaries[0].path
        assert os.path.exists(path)
        removed = mgr.remove()
        assert removed > 0
        assert not os.path.exists(path)

    def test_shannon_entropy_random(self):
        data = os.urandom(1024)
        entropy = _shannon_entropy(data)
        assert entropy > 7.5

    def test_shannon_entropy_text(self):
        data = b"A" * 1024
        entropy = _shannon_entropy(data)
        assert entropy == 0.0

    def test_check_missing_canary(self, vault_path):
        mgr = CanaryManager(vault_path, watch_dirs=[vault_path])
        canaries = mgr.deploy(names=["test_canary.txt"])
        os.unlink(canaries[0].path)
        result = mgr.check_all()
        assert len(result.missing) == 1
        assert result.missing[0].name == "test_canary.txt"
        assert result.is_clean is False

    def test_check_all_result_structure(self, vault_path):
        mgr = CanaryManager(vault_path, watch_dirs=[vault_path])
        mgr.deploy(names=["test_canary.txt"])
        result = mgr.check_all()
        assert isinstance(result, CanaryCheckResult)
        assert hasattr(result, "triggered")
        assert hasattr(result, "missing")
        assert hasattr(result, "is_clean")
        assert hasattr(result, "has_alerts")
        assert result.is_clean is True
        assert result.has_alerts is False

    def test_manifest_hmac_detects_tamper(self, vault_path):
        mgr = CanaryManager(vault_path, watch_dirs=[vault_path])
        mgr.deploy(names=["test_canary.txt"])
        sig_path = mgr._manifest_path.with_suffix(".json.hmac")
        sig_path.write_text("0000000000000000000000000000000000000000000000000000000000000000")
        from aegis._errors import AuditIntegrityError
        with pytest.raises(AuditIntegrityError):
            CanaryManager(vault_path, watch_dirs=[vault_path])

    def test_entropy_threshold_detection(self, vault_path):
        mgr = CanaryManager(vault_path, watch_dirs=[vault_path])
        canaries = mgr.deploy(names=["test_canary.txt"])
        low_entropy_data = b"\x00" * 512
        with open(canaries[0].path, "wb") as f:
            f.write(low_entropy_data)
        result = mgr.check_all()
        assert len(result.triggered) == 1
        _, entropy, low_entropy = result.triggered[0]
        assert low_entropy is True
        assert entropy < 1.0

    def test_deploy_permission_error(self, vault_path, monkeypatch):
        def fail_write(self, data):
            raise PermissionError("simulated")
        monkeypatch.setattr(Path, "write_bytes", fail_write)
        mgr = CanaryManager(vault_path, watch_dirs=[vault_path])
        created = mgr.deploy(names=["test_canary.txt"])
        assert len(created) == 0

    def test_monitor_once_returns_result(self, vault_path):
        mgr = CanaryManager(vault_path, watch_dirs=[vault_path])
        mgr.deploy(names=["test_canary.txt"])
        result = mgr.monitor_once()
        assert isinstance(result, CanaryCheckResult)
        assert result.is_clean is True

    def test_manifest_hmac_valid(self, vault_path):
        mgr = CanaryManager(vault_path, watch_dirs=[vault_path])
        mgr.deploy(names=["test_canary.txt"])
        reloaded = CanaryManager(vault_path, watch_dirs=[vault_path])
        assert len(reloaded._canaries) > 0

    def test_high_entropy_not_flagged(self, vault_path):
        mgr = CanaryManager(vault_path, watch_dirs=[vault_path])
        canaries = mgr.deploy(names=["test_canary.txt"])
        high_entropy_data = os.urandom(512)
        with open(canaries[0].path, "wb") as f:
            f.write(high_entropy_data)
        result = mgr.check_all()
        assert len(result.triggered) == 1
        _, entropy, low_entropy = result.triggered[0]
        assert low_entropy is False
        assert entropy > 7.0
