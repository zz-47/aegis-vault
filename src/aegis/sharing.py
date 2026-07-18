from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aegis._errors import ItemNotFoundError, PermissionError, CryptoError

_WRAP_LABEL = b"seal-key-wrap-v1"
_STANZAS_FILE = "stanzas.json"
_MANIFEST_DIR = "keys"


def _wrap_dek_for_user(dek: bytes, recipient_pub: X25519PublicKey) -> dict:
    ephemeral_priv = X25519PrivateKey.generate()
    ephemeral_pub = ephemeral_priv.public_key()

    shared_secret = ephemeral_priv.exchange(recipient_pub)
    wrap_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=ephemeral_pub.public_bytes_raw() + recipient_pub.public_bytes_raw(),
        info=_WRAP_LABEL,
    ).derive(shared_secret)
    
    nonce = os.urandom(12)
    ct = AESGCM(wrap_key).encrypt(nonce, dek, None)

    return {
        "epk": ephemeral_pub.public_bytes_raw().hex(),
        "nonce": nonce.hex(),
        "wrapped": ct.hex(),
    }

def _unwrap_dek_from_stanza(
        stanza: dict, my_priv: X25519PrivateKey
) -> Optional[bytes]:
    try:
        epk = X25519PublicKey.from_public_bytes(bytes.fromhex(stanza["epk"]))
        shared_secret = my_priv.exchange(epk)
        recipient_pub = my_priv.public_key()

        wrap_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=epk.public_bytes_raw() + recipient_pub.public_bytes_raw(), 
            info=_WRAP_LABEL,
        ).derive(shared_secret)

        return AESGCM(wrap_key).decrypt(
            bytes.fromhex(stanza["nonce"]),
            bytes.fromhex(stanza["wrapped"]),
            None,
        )
    except Exception:
        return None
    

class ShareManager:

    def __init__(self, vault_path: str | Path):
        self._base = Path(vault_path).resolve()
        self._keys_dir = self._base / _MANIFEST_DIR
        self._keys_dir.mkdir(parents=True, exist_ok=True)
        self._stanzas_path = self._keys_dir / _STANZAS_FILE
        self._stanzas: list[dict] = self._load()

    def _load(self) -> list[dict]:
        if not self._stanzas_path.exists():
            return []
        return json.loads(self._stanzas_path.read_text())
    
    def _persist(self) -> None:
        tmp = self._stanzas_path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(self._stanzas, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._stanzas_path)

    def generate_keypair(self) -> tuple[str, str]:
        priv = X25519PrivateKey.generate()
        pub = priv.public_key()
        priv_hex = priv.private_bytes_raw().hex()
        pub_hex = pub.public_bytes_raw().hex()
        user_id = hashlib.sha256(pub_hex.encode()).hexdigest()[:16]
        return user_id, pub_hex
    
    def share_vault(self, user_id: str, pubkey_hex: str,
                dek: bytes) -> None:
        
        pub_bytes = bytes.fromhex(pubkey_hex)
        if len(pub_bytes) != 32:
            raise CryptoError(
                f"Public key must be 32 bytes, got {len(pub_bytes)}.",
                hint="Generate a new keypair with: seal keygen",
                code="invalid_public_key",
            )
        pub =X25519PublicKey.from_public_bytes(pub_bytes)
        stanza = {
            "user_id": user_id,
            **_wrap_dek_for_user(dek, pub),
        }
        self._stanzas.append(stanza)
        self._persist()


    def unshare_vault(self, user_id: str) -> bool:
        original_len = len(self._stanzas)
        self._stanzas = [
            s for s in self._stanzas if s.get("user_id") != user_id
        ]
        if len(self._stanzas) == original_len:
            return False
        self._persist()
        return True
    
    def list_users(self) -> list[str]:
        return [s.get("user_id", "unknown") for s in self._stanzas]
    
    def try_unlock(self, privkey_hex: str) -> Optional[bytes]:
        priv_bytes = bytes.fromhex(privkey_hex)
        if len(priv_bytes) != 32:
            raise CryptoError(
                f"Private key must be 32 bytes, got {len(priv_bytes)}.",
                hint="Generate a new keypair with: seal keygen",
                code="invalid_private_key",
            )
        priv = X25519PrivateKey.from_private_bytes(priv_bytes)
        for stanza in self._stanzas:
            dek = _unwrap_dek_from_stanza(stanza, priv)
            if dek is not None:
                return dek
        return None
    
    def export_stanza(self) -> str:
        return json.dumps(self._stanzas, indent=2)
    
    def import_stanza(self, data: str) -> int:
        stanzas = json.loads(data)
        count = len(stanzas)
        self._stanzas.extend(stanzas)
        self._persist()
        return count