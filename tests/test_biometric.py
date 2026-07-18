import sys
from unittest.mock import MagicMock, patch

import pytest
from aegis._errors import ConfigError, PermissionError
from aegis.biometric import BiometricUnlock


class TestBiometricUnlock:

    @pytest.fixture
    def mock_keyring(self):
        kr = MagicMock()
        kr.get_password.return_value = None
        kr.set_password.return_value = None
        kr.delete_password.return_value = None
        kr.errors.PasswordDeleteError = type("PasswordDeleteError", (Exception,), {})
        return kr

    @pytest.fixture
    def bio_configured(self, mock_keyring):
        with patch.dict("sys.modules", {
            "keyring": mock_keyring,
            "pylocalauth": MagicMock(),
        }):
            bio = BiometricUnlock(vault_id="test_vault")
            bio._keyring = mock_keyring
            bio._has_biometric = False
            bio._authenticate = None
            yield bio, mock_keyring

    def test_setup_stores_passphrase(self, bio_configured):
        bio, mock_kr = bio_configured
        bio.setup("my-secret-passphrase")
        mock_kr.set_password.assert_called_once_with(
            "seal-vault", "test_vault", "my-secret-passphrase"
        )

    def test_unlock_returns_passphrase(self, bio_configured):
        bio, mock_kr = bio_configured
        mock_kr.get_password.return_value = "stored-passphrase"
        bio.setup("stored-passphrase")
        mock_kr.get_password.return_value = "stored-passphrase"
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True
            with patch("getpass.getpass", return_value="stored-passphrase"):
                result = bio.unlock()
        assert result == "stored-passphrase"

    def test_unlock_wrong_passphrase_raises(self, bio_configured):
        bio, mock_kr = bio_configured
        mock_kr.get_password.return_value = "correct-passphrase"
        bio.setup("correct-passphrase")
        mock_kr.get_password.return_value = "correct-passphrase"
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True
            with patch("getpass.getpass", return_value="wrong-passphrase"):
                with pytest.raises(PermissionError) as exc_info:
                    bio.unlock()
                assert exc_info.value.code == "passphrase_wrong"

    def test_unlock_no_keyring_raises(self):
        with patch.dict("sys.modules", {"keyring": None}):
            bio = BiometricUnlock(vault_id="test")
            bio._keyring = None
            with pytest.raises(ConfigError):
                bio.unlock()

    def test_is_configured_true(self, bio_configured):
        bio, mock_kr = bio_configured
        mock_kr.get_password.return_value = "some-pass"
        assert bio.is_configured() is True

    def test_is_configured_false(self, bio_configured):
        bio, mock_kr = bio_configured
        mock_kr.get_password.return_value = None
        assert bio.is_configured() is False

    def test_remove_deletes_password(self, bio_configured):
        bio, mock_kr = bio_configured
        result = bio.remove()
        mock_kr.delete_password.assert_called_once()
        assert result is True
