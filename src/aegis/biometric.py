from __future__ import annotations

import logging
import sys
from typing import Optional

from aegis._errors import PermissionError, ConfigError

logger = logging.getLogger("seal.biometric")

_SERVICE_NAME = "seal-vault"

class BiometricUnlock:

    def __init__(self, vault_id: str = "default"):
        self._vault_id = vault_id
        self._keyring = None
        self._has_biometric = False
        self._init_keyring()

    def _init_keyring(self) -> None:
        try:
            import keyring
            self._keyring = keyring
        except ImportError:
            logger.warning(
                "keyring library not installed. "
                "Install with: pip install keyring"
            )
            return
        
        try:
            from pylocalauth import authenticate
            self._has_biometric = True
            self._authenticate = authenticate
        except ImportError:
            logger.info(
                "pylocalauth not installed. Biometric unlock unavailable. "
                "Install with: pip install pylocalauth"
            )
            self._authenticate = None

    def is_configured(self) -> bool:
        if self._keyring is None:
            return False
        return self._keyring.get_password(_SERVICE_NAME, self._vault_id) is not None
    
    def setup(self, passphrase: str) -> None:
        if self._keyring is None:
            raise ConfigError(
                "keyring library not installed.",
                hint="Install with: pip install keyring",
                code="keyring_not_installed",
            )
        self._keyring.set_password(_SERVICE_NAME, self._vault_id, passphrase)
        
    def unlock(self) -> Optional[str]:
        if self._keyring is None:
            raise ConfigError(
                "keyring library not installed.",
                hint="Install with: pip install keyring",
                code="keyring_not_installed",
            )
        
        if self._has_biometric and self._authenticate is not None:
            message = f"Authenticate to unlock vault '{self._vault_id}'"
            if not self._authenticate(message=message):
                raise PermissionError(
                    "Biometric authentication failed.",
                    hint="Try again or use --passphrase flag.",
                    code="biometric_failed",
                )
        
        else:
            if sys.stdin.isatty():
                import getpass
                pw = getpass.getpass(
                    f"Enter master password for vault '{self._vault_id}': "
                )
                stored = self._keyring.get_password(_SERVICE_NAME, self._vault_id)
               
                if stored and pw == stored:
                    return stored
                raise PermissionError(
                    "Incorrect master password.",
                    hint="Use --passphrase flag or enroll fingerprint.",
                    code="passphrase_wrong",
                )
            else: 
                raise PermissionError(
                    "No biometric available and stdin is not a TTY.",
                    hint="Use --passphrase flag.",
                    code="no_auth_method",
                )
        
        passphrase = self._keyring.get_password(_SERVICE_NAME, self._vault_id)
        if passphrase is None:
            raise PermissionError(
                f"No passphrase stored for vault '{self._vault_id}'.",
                hint="Run: seal vault-setup --passphrase 'your-secret'",
                code="no_stored_passphrase",
            )
        return passphrase
    
    def remove(self) -> bool:
        if self._keyring is None:
            return False
        try: 
            self._keyring.delete_password(_SERVICE_NAME, self._vault_id)
            return True
        except self._keyring.errors.PasswordDeleteError:
            return False
        