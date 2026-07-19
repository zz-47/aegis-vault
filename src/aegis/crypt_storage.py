from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional

from aegis.key_manager import KeyManager
from aegis._errors import LocalStorageError, ItemNotFoundError, ManifestError

_MANIFEST_DIR = "keys"
_MANIFEST_FILE = "manifest.enc"
_NAMESPACES = {"personal", "work", "archive"}
_AAD_NAMESPACE_PREFIX = b"aegis_ns:"


class AegisVault:

    def __init__(
        self,
        base_path: str | Path,
        passphrase: str,
        km_overrides: Optional[dict] = None,
        secure_delete: bool = True,
        cipher_suite: Optional[str] = None,
    ) -> None:
        self._base_path = Path(base_path).resolve()
        self._km = KeyManager(passphrase, overrides=km_overrides, cipher_suite=cipher_suite)
        self._secure_delete = secure_delete
        self._keys_dir = self._base_path / _MANIFEST_DIR
        self._keys_dir.mkdir(parents=True, exist_ok=True)
        if self._km._salt is None:
            self._km.derive_master_key()
        self._manifest = self._load_manifest()
        self._manifest_dirty = False

    def _item_path(self, namespace: str, item_id: str) -> Path:
        return self._base_path / namespace / f"{item_id}.enc"

    def _load_manifest(self) -> dict:
        path = self._keys_dir / _MANIFEST_FILE
        if not path.exists():
            return {"version": 1, "items": {}}
        blob = path.read_bytes()
        return self._km.import_encrypted_manifest(blob)

    def _save_manifest(self) -> None:
        blob = self._km.export_encrypted_manifest(self._manifest)
        tmp = self._keys_dir / f".{_MANIFEST_FILE}.tmp"
        with open(tmp, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._keys_dir / _MANIFEST_FILE)

    def save(self, namespace: str, item_id: str, data: dict) -> None:

        if namespace not in _NAMESPACES:
            raise LocalStorageError(
                f"Unknown namespace '{namespace}'. Valid: {_NAMESPACES}",
                hint="Use one of the registered namespaces.",
                code="invalid_namespace",
            )

        items = self._manifest.setdefault("items", {})

        if item_id in items:
            dek = self._km.get_dek(item_id, self._manifest)
        else:
            dek = self._km.generate_dek()
            wrapped = self._km.wrap_dek(dek, item_id.encode())
            items[item_id] = {
                "namespace": namespace,
                "dek": wrapped,
                "created": time.time(),
            }
            self._manifest_dirty = True

        json_bytes = json.dumps(data, separators=(",", ":")).encode("utf-8")
        aad = _AAD_NAMESPACE_PREFIX + f"{namespace}:{item_id}".encode()
        blob = self._km._cipher.encrypt_combined(dek, json_bytes, aad)

        path = self._item_path(namespace, item_id)
        ns_dir = self._base_path / namespace
        ns_dir.mkdir(parents=True, exist_ok=True)

        tmp = path.with_suffix(".tmp")
        with open(tmp, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

        if self._manifest_dirty:
            self._save_manifest()
            self._manifest_dirty = False

    def load(self, namespace: str, item_id: str) -> dict:

        if namespace not in _NAMESPACES:
            raise LocalStorageError(
                f"Unknown namespace '{namespace}'. Valid: {_NAMESPACES}",
                hint="Use one of the registered namespaces.",
                code="invalid_namespace",
            )

        path = self._item_path(namespace, item_id)
        if not path.exists():
            raise ItemNotFoundError(
                f"Item '{item_id}' not found in namespace '{namespace}'.",
                hint="Check that the item was saved before loading.",
                code="item_not_found",
            )

        try:
            blob = path.read_bytes()
        except FileNotFoundError:
            raise ItemNotFoundError(
                f"Item '{item_id}' not found in namespace '{namespace}'.",
                hint="The file may have been deleted or moved.",
                code="item_not_found",
            )

        dek = self._km.get_dek(item_id, self._manifest)
        aad = _AAD_NAMESPACE_PREFIX + f"{namespace}:{item_id}".encode()
        decrypted = self._km._cipher.decrypt_combined(dek, blob, aad)
        return json.loads(decrypted.decode("utf-8"))

    def delete(self, namespace: str, item_id: str) -> None:

        if namespace not in _NAMESPACES:
            raise LocalStorageError(
                f"Unknown namespace '{namespace}'. Valid: {_NAMESPACES}",
                hint="Use one of the registered namespaces.",
                code="invalid_namespace",
            )

        path = self._item_path(namespace, item_id)
        if not path.exists():
            raise ItemNotFoundError(
                f"Item '{item_id}' not found in namespace '{namespace}'.",
                hint="Check the item_id before deleting.",
                code="item_not_found",
            )

        if self._secure_delete:
            length = path.stat().st_size
            with open(path, "wb") as f:
                f.write(os.urandom(length))
                f.flush()
                os.fsync(f.fileno())
        path.unlink()

        items = self._manifest.get("items")
        if items is not None:
            items.pop(item_id, None)
            self._manifest_dirty = True
        self._save_manifest()
        self._manifest_dirty = False

    def list_items(self, namespace: str) -> list[str]:

        ns_dir = self._base_path / namespace
        if not ns_dir.exists():
            return []
        return sorted(p.stem for p in ns_dir.glob("*.enc"))