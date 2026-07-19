from __future__ import annotations

import os
import json
import base64
import binascii
import hashlib
import re
from typing import Optional

from aegis.cipher import AeadCipher
from aegis._errors import LocalStorageError, ManifestError, ItemNotFoundError

# PBKDF2 parameters — OWASP 2023 minimum
_PBKDF2_ITERATIONS = 600_000
_KEY_SIZE_BYTES = 32       # AES-256
_SALT_SIZE_BYTES = 16
_AUTH_TAG_SIZE = 16

# AAD tags — bind ciphertext to purpose so different contexts can't swap blobs
_AAD_MANIFEST = b"aegis_manifest_v1"
_AAD_DEK_WRAP = b"aegis_dek_wrap_v1"

# In-memory DEK cache size
_MAX_CACHED_DEKS = 128

_B64_PATTERN = re.compile(r"^[A-Za-z0-9_-]+=*$")


def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64_decode(s: str) -> bytes:
    if not _B64_PATTERN.match(s):
        raise LocalStorageError(
            "Invalid base64 input — data may be corrupted.",
            hint="The wrapped DEK string contains invalid characters.",
            code="invalid_base64",
        )
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    try:
        return base64.urlsafe_b64decode(s)
    except binascii.Error:
        raise LocalStorageError(
            "Invalid base64 input — data may be corrupted.",
            hint="The wrapped DEK string contains invalid characters.",
            code="invalid_base64",
        )


class KeyManager:

    def __init__(self, passphrase: str, overrides: Optional[dict] = None,
                 cipher_suite: Optional[str] = None):
        from aegis.cipher import CipherConfig, CipherSuite

        self._passphrase = passphrase.encode("utf-8")
        self._master_key: Optional[bytes] = None

        if cipher_suite == "chacha20":
            config = CipherConfig(suite=CipherSuite.CHACHA20_POLY1305)
        else:
            config = CipherConfig()
        self._cipher = AeadCipher(config)

        self._dek_cache: dict[bytes, bytes] = {}
        self._salt: Optional[bytes] = None
        self._pbkdf2_iterations = (overrides or {}).get("pbkdf2_iterations", _PBKDF2_ITERATIONS)
        self._max_cached_deks = (overrides or {}).get("max_cached_deks", _MAX_CACHED_DEKS)

    def derive_master_key(self, salt: Optional[bytes] = None) -> bytes:

        if salt is None:
            salt = os.urandom(_SALT_SIZE_BYTES)

        if len(salt) != _SALT_SIZE_BYTES:
            raise LocalStorageError(
                f"Salt must be {_SALT_SIZE_BYTES} bytes (got {len(salt)}).",
                hint="Use os.urandom(16) to generate valid salt.",
                code="invalid_salt_size",
            )

        master_key = hashlib.pbkdf2_hmac(
            "sha256", self._passphrase, salt,
            self._pbkdf2_iterations, dklen=_KEY_SIZE_BYTES,
        )
        self._master_key = master_key
        self._salt = salt
        return master_key

    def generate_dek(self) -> bytes:
        return os.urandom(_KEY_SIZE_BYTES)

    def wrap_dek(self, dek: bytes, item_id: bytes) -> str:

        if self._master_key is None:
            raise LocalStorageError(
                "Master Key not derived. Call derive_master_key(salt) first.",
                hint="Derive the Master Key before wrapping DEKs.",
                code="master_key_missing",
            )

        aad = _AAD_DEK_WRAP + item_id
        blob = self._cipher.encrypt_combined(self._master_key, dek, aad)
        return _b64_encode(blob)

    def unwrap_dek(self, wrapped_b64: str, item_id: bytes) -> bytes:

        if self._master_key is None:
            raise LocalStorageError(
                "Master Key not derived. Call derive_master_key(salt) first.",
                hint="Derive the Master Key before unwrapping DEKs.",
                code="master_key_missing",
            )

        blob = _b64_decode(wrapped_b64)
        aad = _AAD_DEK_WRAP + item_id
        return self._cipher.decrypt_combined(self._master_key, blob, aad)

    def cache_dek(self, item_id: bytes, dek: bytes) -> None:

        cache_key = hashlib.sha256(item_id).digest()
        self._dek_cache[cache_key] = dek

        if len(self._dek_cache) > self._max_cached_deks:
            oldest = next(iter(self._dek_cache))
            del self._dek_cache[oldest]

    def get_cached_dek(self, item_id: bytes) -> Optional[bytes]:

        cache_key = hashlib.sha256(item_id).digest()
        return self._dek_cache.get(cache_key)

    def export_encrypted_manifest(self, manifest: dict) -> bytes:

        if self._master_key is None or self._salt is None:
            raise ManifestError(
                "Master Key not derived. Call derive_master_key() first.",
                hint="Derive the Master Key before exporting the manifest.",
                code="master_key_missing",
            )

        payload = json.dumps(manifest, separators=(",", ":")).encode("utf-8")
        encrypted = self._cipher.encrypt_combined(
            self._master_key, payload, _AAD_MANIFEST,
        )
        return self._salt + encrypted

    def import_encrypted_manifest(self, blob: bytes) -> dict:

        if len(blob) < _SALT_SIZE_BYTES + _AUTH_TAG_SIZE + 1:
            raise ManifestError(
                "Manifest blob is too small to be valid.",
                hint="File may be corrupted or truncated.",
                code="manifest_corrupted",
            )

        salt = blob[:_SALT_SIZE_BYTES]
        encrypted = blob[_SALT_SIZE_BYTES:]

        self.derive_master_key(salt)
        if self._master_key is None:
            raise ManifestError(
                "Master Key derivation failed — derive_master_key did not set a key.",
                hint="This indicates a bug in key derivation logic.",
                code="master_key_not_set",
            )

        payload = self._cipher.decrypt_combined(
            self._master_key, encrypted, _AAD_MANIFEST,
        )
        return json.loads(payload.decode("utf-8"))

    def get_dek(self, item_id: str, manifest: dict) -> bytes:

        id_bytes = item_id.encode("utf-8")
        cache_key = hashlib.sha256(id_bytes).digest()

        cached = self._dek_cache.get(cache_key)
        if cached is not None:
            return cached

        items = manifest.get("items", {})
        entry = items.get(item_id)
        if entry is None:
            raise ItemNotFoundError(
                f"Item '{item_id}' not found in manifest.",
                hint="Check that the item was saved before loading.",
                code="manifest_item_missing",
            )

        dek_raw = entry.get("dek")
        if dek_raw is None:
            raise ManifestError(
                f"Manifest entry for '{item_id}' is missing 'dek' field.",
                hint="The manifest file may be corrupted. Check data/keys/manifest.enc.",
                code="manifest_entry_corrupted",
            )

        dek = self.unwrap_dek(dek_raw, id_bytes)

        self._dek_cache[cache_key] = dek
        if len(self._dek_cache) > self._max_cached_deks:
            oldest = next(iter(self._dek_cache))
            del self._dek_cache[oldest]
        return dek