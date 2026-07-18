# covers unauth personel detect.
from __future__ import annotations

import hashlib
import math
import os
import json
from collections import Counter
from pathlib import Path
from typing import Callable, Optional

from aegis._errors import PermissionError

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
        data = json.loads(self._manifest_path.read_text())
        return [CanaryFile.from_dict(c) for c in data]   

    def _save_manifest(self) -> None:
        import json
        data = [c.to_dict() for c in self._canaries] 
        tmp = self._manifest_path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._manifest_path)

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
                canary_path.write_bytes(content)
                cf = CanaryFile(name, str(canary_path), h, entropy)  
                new_canaries.append(cf)
                self._canaries.append(cf)

        self._save_manifest()
        return new_canaries
    
    def check_all(self) -> list[tuple[CanaryFile, float]]:
        triggered = []
        for canary in self._canaries:
            path = Path(canary.path)
            if not path.exists():
                continue
            content = path.read_bytes()
            current_hash = hashlib.sha256(content).hexdigest()
            if current_hash != canary.original_hash:
                current_entropy = _shannon_entropy(content)
                triggered.append((canary, current_entropy)) 
                if self._on_trigger:
                    self._on_trigger(canary.path, current_entropy) 
        return triggered
    
    # decoy track
    def monitor_once(self) -> list[CanaryFile]:
        triggered = self.check_all()
        if triggered:
            paths = [c.path for c, _ in triggered]
            raise PermissionError(
                    f"Ransomware canary triggered: {paths}",
                    hint="Unauthorized mass encryption detected. Vault frozen.",
                    code="canary_triggered",
            )
        return []
    
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
        
         



