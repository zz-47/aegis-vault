from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Optional

from aegis._errors import IntegrityError

_AUDIT_DIR = "keys"
_AUDIT_FILE = "audit.log"
_GENESIS_HASH = "0" * 64

def _hash_entry(seq: int, ts: float, op: str, namespace: str,
        item_id: str, prev_hash: str) -> str:
    
    payload = f"{seq}:{ts}:{op}:{namespace}:{item_id}:{prev_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

class AuditEntry:
    __slots__ = ("seq", "ts", "op", "namespace", "item_id",
                 "prev_hash", "hash")

    def __init__(self, seq: int, ts: float, op: str, namespace: str,
                 item_id: str, prev_hash: str, hash: str):
        self.seq = seq
        self.ts = ts
        self.op = op
        self.namespace = namespace
        self.item_id = item_id
        self.prev_hash = prev_hash
        self.hash = hash

    def to_dict(self) -> dict:
        return {
            "seq": self.seq,
            "ts": self.ts, # time
            "op": self.op,
            "namespace": self.namespace,
            "item_id": self.item_id,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }
    
    @classmethod
    def _from_dict(cls, d: dict) -> AuditEntry:
        return cls(
            seq=d["seq"], ts=d["ts"], op=d["op"],
            namespace = d["namespace"], item_id = d["item_id"],
            prev_hash = d["prev_hash"], hash = d["hash"],
        )
    
class AuditLog:
    def __init__(self, vault_path: str | Path):
        self._base = Path(vault_path).resolve()
        self._audit_dir = self._base / _AUDIT_DIR
        self._audit_dir.mkdir(parents=True, exist_ok=True)
        self._path = self._audit_dir / _AUDIT_FILE
        self._entries: list[AuditEntry] = self._load()

    def _load(self) -> list[AuditEntry]:
        if not self._path.exists():
            return []
        entries = []
        for line in self._path.read_text().splitlines():
            line = line.strip()
            if line:
                entries.append(AuditEntry._from_dict(json.loads(line)))
        return entries

    def _persist(self) -> None:
        tmp = self._path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            for entry in self._entries:
                f.write(json.dumps(entry.to_dict(), separators=(",",":")) + "\n")
            f.flush()   
            import os
            os.fsync(f.fileno())
        import os
        os.replace(tmp, self._path)

    def append(self, op:str, namespace: str, item_id: str) -> AuditEntry:
        seq = len(self._entries) + 1
        ts = time.time()   
        prev_hash = self._entries[-1].hash if self._entries else _GENESIS_HASH
        h = _hash_entry(seq, ts, op, namespace, item_id, prev_hash)
        entry = AuditEntry(seq, ts, op, namespace, item_id, prev_hash, h)
        self._entries.append(entry)
        self._persist()   
        return entry

    def verify(self) -> bool:
        prev = _GENESIS_HASH
        for entry in self._entries:
            expected = _hash_entry(
                entry.seq, entry.ts, entry.op,
                entry.namespace, entry.item_id, prev,
            )   
            if entry.hash != expected:
                return False
            prev = entry.hash
        return True
    
    def get_entries(
            self,
            namespace: Optional[str] = None,
            op: Optional[str] = None,
            since: Optional[float] = None,
    ) -> list[AuditEntry]:
        result = self._entries

        if namespace is not None:
            result = [e for e in result if e.namespace == namespace]
        if op is not None:
            result = [e for e in result if e.op == op] 
        if since is not None:
            result = [e for e in result if e.ts >= since] # time duration
        return result
    
    def export_json(self) -> str:
        return json.dumps(
            [e.to_dict() for e in self._entries],
            indent=2, separators=(",",":"),
        )
    
    @property
    def entry_count(self) -> int:
        return len(self._entries)
    
    @property
    def last_hash(self) -> str:
        return self._entries[-1].hash if self._entries else _GENESIS_HASH
