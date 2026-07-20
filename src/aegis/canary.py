# covers unauth personel detect.
from __future__ import annotations

import hashlib
import json
import math
import os
import hmac
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from aegis._errors import PermissionError

@dataclass
class CanaryCheckResult:  # integrity check.
    triggered: list  # list of (CanaryFile, float) — modified files with current entropy
    missing: list    # list of CanaryFile — files that were deleted

    @property
    def is_clean(self) -> bool:
        return not self.triggered and not self.missing

    @property
    def has_alerts(self) -> bool:
        return bool(self.triggered or self.missing)    
    

_CANARY_DIR = ".canaries"
_CANARY_MANIFEST = "canaries.json"
_ENTROPY_THRESHOLD = 7.5

# minimzes brute force.
def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    result = 0.0
    for c in counts.values():
        p = c / length
        result -= p * math.log2(p)
    return result

    
def _generate_canary_content() -> tuple[bytes, str, float]:
    content = os.urandom(512)
    h = hashlib.sha256(content).hexdigest()
    entropy = _shannon_entropy(content)
    return content, h, entropy

_HMAC_KEY_SEED = b"seal-canary-manifest"


def _derive_hmac_key(vault_path: Path) -> bytes:
    return hashlib.sha256(_HMAC_KEY_SEED + str(vault_path).encode()).digest()


_DEFAULT_CANARY_NAMES = [
    "passwords.xlsx",
    "financials.pdf",
    "backup_keys.pem",
    "tax_return_2024.docx",
    "wallet.dat",
    "id_scan.jpg",
]

class CanaryFile:
    __slots__ = ("name", "path", "original_hash", "original_entropy")

    def __init__(self, name: str, path: str, original_hash: str,
                 original_entropy: float):
        self.name = name
        self.path = path
        self.original_hash = original_hash
        self.original_entropy = original_entropy

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "original_hash": self.original_hash,
            "original_entropy": self.original_entropy,
        }
    
    @classmethod
    def from_dict(cls, d:dict) -> CanaryFile:
        return cls(d["name"], d["path"], d["original_hash"],
                   d["original_entropy"])
    
class CanaryManager:

    def __init__(
        self,
        vault_path: str | Path,
        watch_dirs: Optional[list[str]] = None,
        entropy_threshold: float = _ENTROPY_THRESHOLD,
        on_trigger: Optional[Callable[[str, float], None]] = None,
    ):
        self._base = Path(vault_path).resolve()
        self._canary_dir = self._base / _CANARY_DIR
        self._canary_dir.mkdir(parents=True, exist_ok=True)
        self._manifest_path = self._canary_dir / _CANARY_MANIFEST
        self._watch_dir = watch_dirs or [
            str(self._base),
            str(Path.home() / "Documents"),
            str(Path.home() / "Desktop"),
        ]
        self._entropy_threshold = entropy_threshold
        self._on_trigger = on_trigger
        self._canaries: list[CanaryFile] = self._load_manifest()

    def _load_manifest(self) -> list[CanaryFile]:
        if not self._manifest_path.exists():
            return []
        payload = self._manifest_path.read_text()

        sig_path = self._manifest_path.with_suffix(".json.hmac")
        if sig_path.exists():
            key = _derive_hmac_key(self._base)
            expected = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
            actual = sig_path.read_text().strip()
            if not hmac.compare_digest(expected, actual):
                from aegis._errors import AuditIntegrityError
                raise AuditIntegrityError(
                    "Canary manifest HMAC mismatch — manifest was tampered with",
                    hint="The canary manifest has been modified outside of Seal.",
                    code="manifest_tampered",
                )

        data = json.loads(payload)
        return [CanaryFile.from_dict(c) for c in data]   

    def _save_manifest(self) -> None:
        data = [c.to_dict() for c in self._canaries]
        payload = json.dumps(data, indent=2).encode()
        key = _derive_hmac_key(self._base)
        sig = hmac.new(key, payload, hashlib.sha256).hexdigest()

        tmp = self._manifest_path.with_suffix(".tmp")
        with open(tmp, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._manifest_path)

        sig_path = self._manifest_path.with_suffix(".json.hmac")
        tmp_sig = sig_path.with_suffix(".hmac.tmp")
        with open(tmp_sig, "w") as f:
            f.write(sig)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_sig, sig_path)

    # decoys
    def deploy(self, names: Optional[list[str]] = None) -> list[CanaryFile]:
        names = names or _DEFAULT_CANARY_NAMES
        new_canaries = []
        for watch_dir in self._watch_dir:
            watch_path = Path(watch_dir)
            if not watch_path.exists():
                continue
            for name in names:
                canary_path = watch_path / name
                if canary_path.exists():
                    continue
                content, h, entropy = _generate_canary_content()
                try:
                    canary_path.write_bytes(content)
                except:
                    continue
                cf = CanaryFile(name, str(canary_path), h, entropy)  
                new_canaries.append(cf)
                self._canaries.append(cf)

        self._save_manifest()
        return new_canaries
    
    def check_all(self) -> CanaryCheckResult:
        triggered = []
        missing = []
        for canary in self._canaries:
            path = Path(canary.path)
            if not path.exists():
                missing.append(canary)
                continue
            content = path.read_bytes()
            current_hash = hashlib.sha256(content).hexdigest()
            if current_hash != canary.original_hash:
                current_entropy = _shannon_entropy(content)
                low_entropy = current_entropy < self._entropy_threshold
                triggered.append((canary, current_entropy, low_entropy))
                if self._on_trigger:
                    self._on_trigger(canary.path, current_entropy) 
        return CanaryCheckResult(triggered=triggered, missing=missing)
    
    # decoy track
    def monitor_once(self) -> CanaryCheckResult:
        result = self.check_all()
        if result.has_alerts:
            paths = [c.path for c, _, _ in result.triggered] + [c.path for c in result.missing]
            raise PermissionError(
                    f"Ransomware canary triggered: {paths}",
                    hint="Unauthorized mass encryption detected. Vault frozen.",
                    code="canary_triggered",
            )
        return result
    
    def status(self) -> list[dict]:
        return [
            {
                "name": c.name,
                "path": c.path,
                "exists": Path(c.path).exists(),
                "entropy": c.original_entropy,
            }
            for c in self._canaries
        ]
    
    def remove(self) -> int:
        removed = 0
        for canary in self._canaries:
            path = Path(canary.path)
            if path.exists():
                path.unlink()
                removed += 1
        self._canaries.clear()
        self._save_manifest()
        return removed
        
         



