from __future__ import annotations

import os
from enum import Enum
from dataclasses import dataclass
from typing import Optional
from cryptography.exceptions import InvalidTag

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from aegis._errors import LocalStorageError, DecryptionError


class CipherSuite(Enum):
    """Which AEAD algorithm to use. AES-GCM is the safe default."""
    AES256_GCM = "aes-256-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"


_KEY_SIZES = {
    CipherSuite.AES256_GCM: 32,
    CipherSuite.CHACHA20_POLY1305: 32,
}

_NONCE_SIZES = {
    CipherSuite.AES256_GCM: 12,
    CipherSuite.CHACHA20_POLY1305: 12,
}

_AUTH_TAG_SIZE = 16

 # Immutable configuration for the cipher layer.
@dataclass(frozen=True)
class CipherConfig:

    # Change to CHACHA20_POLY1305 if running on non-x86 hardware           
    suite: CipherSuite = CipherSuite.AES256_GCM

class AeadCipher:

    def __init__(self, config: Optional[CipherConfig] = None):
        self.config = config or CipherConfig()
        self._key_size = _KEY_SIZES[self.config.suite]
        self._nonce_size = _NONCE_SIZES[self.config.suite]
        self._auth_tag_size = _AUTH_TAG_SIZE

    def generate_key(self) -> bytes:
       return os.urandom(self._key_size)
        
    def encrypt(
        self,
        key: bytes,
        plaintext: bytes,
        aad: bytes = b"",
    ) -> tuple[bytes, bytes, bytes]:

        self._validate_key_size(key)

        nonce = os.urandom(self._nonce_size)

        if self.config.suite == CipherSuite.AES256_GCM:
            aead = AESGCM(key)
        else:
            aead = ChaCha20Poly1305(key)

        ct_with_tag = aead.encrypt(nonce, plaintext, aad)

        ciphertext = ct_with_tag[:-self._auth_tag_size]
        auth_tag = ct_with_tag[-self._auth_tag_size:]

        return ciphertext, nonce, auth_tag
        
    def encrypt_combined(
        self,
        key: bytes,
        plaintext: bytes,
        aad: bytes = b"",
    ) -> bytes:

        ciphertext, nonce, auth_tag = self.encrypt(key, plaintext, aad)
        return nonce + ciphertext + auth_tag
        
    def decrypt(
        self,
        key: bytes,
        ciphertext: bytes,
        nonce: bytes,
        auth_tag: bytes,
        aad: bytes = b"",
    ) -> bytes:

        self._validate_key_size(key)

        ct_with_tag = ciphertext + auth_tag

        if self.config.suite == CipherSuite.AES256_GCM:
            aead = AESGCM(key)
        else:
             aead = ChaCha20Poly1305(key)

        try:
             return aead.decrypt(nonce, ct_with_tag, aad)

        except (InvalidTag, ValueError, TypeError):
            raise DecryptionError(
                "Decryption failed — data may be tampered, key may be wrong,"
                " or AAD may not match.",
                hint="Verify the encryption key and that the file was not modified.",
                code="decryption_failed",
            )

    def decrypt_combined(
        self,
        key: bytes,
        blob: bytes,
        aad: bytes = b"",
    ) -> bytes:  
        
        nonce = blob[:self._nonce_size]
        auth_tag = blob[-self._auth_tag_size:]  
        ciphertext = blob[self._nonce_size:-self._auth_tag_size]
        return self.decrypt(key, ciphertext, nonce, auth_tag, aad)


    def _validate_key_size(self, key: bytes) -> None:

        if len(key) != self._key_size:
            raise LocalStorageError(
                f"Key must be exactly {self._key_size} bytes"
                f" got {len(key)} bytes.",
                hint=f"Call generate_key() to create a valid"
                    f" {self._key_size}-byte key.",
                code="invalid_key_size",
                )