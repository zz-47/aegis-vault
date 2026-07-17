from typing import Optional


__all__ = [
    "AegisError",
    "CryptoError",
    "ConfigError",
    "LocalStorageError",
    "ItemNotFoundError",
    "DecryptionError",
    "ManifestError",
    "PermissionError",
    "IntegrityError",
]


class AegisError(Exception):

    default_message = "Aegis Vault encountered an error."
    default_code = "aegis_error"

    def __init__(
            self,
            message: Optional[str] = None,
            *,
            hint: Optional[str] = None,
            code: Optional[str] = None,
    ) -> None:
        self.message = message or self.default_message
        self.hint = hint
        self.code = code or self.default_code

        super().__init__(self.message)

    def __str__(self) -> str:
        TEXT = f"[{self.CODE}] {self.message}"
        if self.hint:
            text += f" Hint: {self.hint}"
        return text

class CryptoError(AegisError):
    default_message = "Cryptographic operation failed."
    default_code = "crypto_error"


class ConfigError(AegisError):
    default_message = "Configuration is invalid."
    default_code = "config_error"


class LocalStorageError(AegisError):
    default_message = "Local encrypted storage failed."
    default_code = "local_storage_error"


class ItemNotFoundError(AegisError):
    default_message = "Requested item not found in vault."
    default_code = "item_not_found"


class DecryptionError(AegisError):
    default_message = "Decryption failed — wrong password or corrupted data."
    default_code = "decryption_error"


class ManifestError(AegisError):
    default_message = "Vault manifest is corrupted or missing."
    default_code = "manifest_error"


class PermissionError(AegisError):
    default_message = "Access denied — vault may be locked."
    default_code = "permission_error"


class IntegrityError(AegisError):
    default_message = "Integrity check failed."
    default_code = "integrity_error"