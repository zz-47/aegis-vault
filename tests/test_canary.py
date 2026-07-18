import os
import shutil
import tempfile

import pytest
from aegis.canary import CanaryManager, _shannon_entropy


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
        triggered = mgr.check_all()
        assert len(triggered) == 0

    def test_tamper_detection(self, vault_path):
        mgr = CanaryManager(vault_path, watch_dirs=[vault_path])
        canaries = mgr.deploy(names=["test_canary.txt"])
        with open(canaries[0].path, "wb") as f:
            f.write(os.urandom(1024))
        triggered = mgr.check_all()
        assert len(triggered) > 0

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