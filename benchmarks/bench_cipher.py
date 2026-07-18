#!/usr/bin/env python3
"""Seal benchmarks — cipher throughput, KDF, roundtrip, audit log.

Usage:
    python benchmarks/bench_cipher.py          # run all, print + write RESULTS.md
    python benchmarks/bench_cipher.py --json   # also dump raw JSON to stdout
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import platform
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from aegis.cipher import AeadCipher, CipherConfig, CipherSuite
from aegis.key_manager import KeyManager
from aegis.audit import AuditLog
from aegis.crypt_storage import AegisVault

# ─── Sizes ────────────────────────────────────────────────────────────

_SIZES = [64, 256, 1024, 4096, 65536, 262144, 1048576]
_SIZE_LABELS = ["64B", "256B", "1KB", "4KB", "64KB", "256KB", "1MB"]
_CIPHER_ITERS = 1000
_KDF_RUNS = 10
_DEK_ITERS = 1000
_ROUNDTRIP_ITERS = 100
_AUDIT_ITERS = 1000


def _fmt_size(n: int) -> str:
    if n >= 1048576:
        return f"{n / 1048576:.0f}MB"
    if n >= 1024:
        return f"{n / 1024:.0f}KB"
    return f"{n}B"


def _median_us(samples: list[float]) -> float:
    return statistics.median(samples) * 1_000_000


def _median_ms(samples: list[float]) -> float:
    return statistics.median(samples) * 1_000


# ─── Benchmark 1 & 2: Cipher throughput ──────────────────────────────

def bench_cipher_throughput(suite: CipherSuite) -> list[dict]:
    cipher = AeadCipher(CipherConfig(suite=suite))
    results = []
    for size, label in zip(_SIZES, _SIZE_LABELS):
        key = cipher.generate_key()
        plaintext = os.urandom(size)
        aad = b"bench:test"
        enc_times = []
        dec_times = []
        for _ in range(_CIPHER_ITERS):
            t0 = time.perf_counter()
            ct, nonce, tag = cipher.encrypt(key, plaintext, aad)
            t1 = time.perf_counter()
            cipher.decrypt(key, ct, nonce, tag, aad)
            t2 = time.perf_counter()
            enc_times.append(t1 - t0)
            dec_times.append(t2 - t1)
        enc_median = statistics.median(enc_times)
        dec_median = statistics.median(dec_times)
        enc_mbps = (size / enc_median) / (1024 * 1024) if enc_median > 0 else 0
        dec_mbps = (size / dec_median) / (1024 * 1024) if dec_median > 0 else 0
        results.append({
            "size": label,
            "enc_us": _median_us(enc_times),
            "dec_us": _median_us(dec_times),
            "enc_mbps": enc_mbps,
            "dec_mbps": dec_mbps,
        })
    return results


# ─── Benchmark 3: PBKDF2 ─────────────────────────────────────────────

def bench_pbkdf2() -> dict:
    times = []
    for _ in range(_KDF_RUNS):
        km = KeyManager("benchmark-passphrase")
        t0 = time.perf_counter()
        km.derive_master_key()
        t1 = time.perf_counter()
        times.append(t1 - t0)
    return {
        "iterations": 600_000,
        "runs": _KDF_RUNS,
        "median_ms": _median_ms(times),
        "min_ms": min(times) * 1000,
        "max_ms": max(times) * 1000,
    }


# ─── Benchmark 4: DEK wrap/unwrap ────────────────────────────────────

def bench_dek_wrap() -> dict:
    km = KeyManager("benchmark-passphrase")
    km.derive_master_key()
    dek = km.generate_dek()
    wrap_times = []
    unwrap_times = []
    for i in range(_DEK_ITERS):
        item_id = f"item_{i}".encode()
        t0 = time.perf_counter()
        wrapped = km.wrap_dek(dek, item_id)
        t1 = time.perf_counter()
        km.unwrap_dek(wrapped, item_id)
        t2 = time.perf_counter()
        wrap_times.append(t1 - t0)
        unwrap_times.append(t2 - t1)
    return {
        "iters": _DEK_ITERS,
        "wrap_median_us": _median_us(wrap_times),
        "unwrap_median_us": _median_us(unwrap_times),
        "total_median_us": _median_us(wrap_times) + _median_us(unwrap_times),
    }


# ─── Benchmark 5: Full save/load roundtrip ───────────────────────────

def bench_roundtrip() -> dict:
    tmp = tempfile.mkdtemp(prefix="seal_bench_")
    try:
        vp = os.path.join(tmp, "vault")
        payload = {"user": "bench", "token": "x" * 64, "meta": {"a": 1, "b": [1, 2, 3]}}
        save_times = []
        load_times = []
        for i in range(_ROUNDTRIP_ITERS):
            v = AegisVault(vp, "bench-pass")
            item_id = f"rt_{i}"
            t0 = time.perf_counter()
            v.save("personal", item_id, payload)
            t1 = time.perf_counter()
            v.load("personal", item_id)
            t2 = time.perf_counter()
            save_times.append(t1 - t0)
            load_times.append(t2 - t1)
        return {
            "iters": _ROUNDTRIP_ITERS,
            "save_median_ms": _median_ms(save_times),
            "load_median_ms": _median_ms(load_times),
            "roundtrip_median_ms": _median_ms(save_times) + _median_ms(load_times),
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ─── Benchmark 6: Audit log append ───────────────────────────────────

def bench_audit_append() -> dict:
    tmp = tempfile.mkdtemp(prefix="seal_bench_audit_")
    try:
        log = AuditLog(tmp)
        times = []
        for i in range(_AUDIT_ITERS):
            t0 = time.perf_counter()
            log.append("save", "personal", f"item_{i}")
            t1 = time.perf_counter()
            times.append(t1 - t0)
        return {
            "iters": _AUDIT_ITERS,
            "append_median_us": _median_us(times),
            "append_p99_us": sorted(times)[int(len(times) * 0.99)] * 1_000_000,
            "total_entries": log.entry_count,
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ─── Metadata ─────────────────────────────────────────────────────────

def _metadata() -> dict:
    try:
        import cryptography
        cRYPTO_VER = cryptography.__version__
    except Exception:
        cRYPTO_VER = "unknown"
    try:
        ssl_ver = hashlib.new("sha256").name  # just for OpenSSL presence
    except Exception:
        ssl_ver = "unknown"
    return {
        "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "arch": platform.machine(),
        "cryptography": cRYPTO_VER,
    }


# ─── Markdown renderer ────────────────────────────────────────────────

def _write_results_md(meta: dict, aes_gcm: list[dict], chacha: list[dict],
                      kdf: dict, dek: dict, rt: dict, audit: dict) -> str:
    lines = [
        "# Seal — Benchmark Results",
        "",
        f"*Generated {meta['date']}*  ",
        f"Platform: `{meta['platform']}` · Python {meta['python']} · "
        f"cryptography {meta['cryptography']} · {meta['arch']}",
        "",
        "---",
        "",
        "## 1. AEAD Cipher Throughput",
        "",
        "### AES-256-GCM",
        "",
        "| Size | Encrypt (µs) | Decrypt (µs) | Enc MB/s | Dec MB/s |",
        "|------|-------------|-------------|----------|----------|",
    ]
    for r in aes_gcm:
        lines.append(
            f"| {r['size']} | {r['enc_us']:.1f} | {r['dec_us']:.1f} "
            f"| {r['enc_mbps']:.1f} | {r['dec_mbps']:.1f} |"
        )
    lines += [
        "",
        "### ChaCha20-Poly1305",
        "",
        "| Size | Encrypt (µs) | Decrypt (µs) | Enc MB/s | Dec MB/s |",
        "|------|-------------|-------------|----------|----------|",
    ]
    for r in chacha:
        lines.append(
            f"| {r['size']} | {r['enc_us']:.1f} | {r['dec_us']:.1f} "
            f"| {r['enc_mbps']:.1f} | {r['dec_mbps']:.1f} |"
        )
    lines += [
        "",
        "---",
        "",
        "## 2. PBKDF2 Key Derivation (SHA-256, 600K iterations)",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Median | {kdf['median_ms']:.1f} ms |",
        f"| Min | {kdf['min_ms']:.1f} ms |",
        f"| Max | {kdf['max_ms']:.1f} ms |",
        "",
        "---",
        "",
        "## 3. DEK Wrap / Unwrap (AES-GCM envelope)",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Wrap median | {dek['wrap_median_us']:.1f} µs |",
        f"| Unwrap median | {dek['unwrap_median_us']:.1f} µs |",
        f"| Total roundtrip | {dek['total_median_us']:.1f} µs |",
        "",
        "---",
        "",
        "## 4. Full Save → Load Roundtrip",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Save median | {rt['save_median_ms']:.2f} ms |",
        f"| Load median | {rt['load_median_ms']:.2f} ms |",
        f"| Roundtrip median | {rt['roundtrip_median_ms']:.2f} ms |",
        f"| Iterations | {rt['iters']} |",
        "",
        "---",
        "",
        "## 5. Audit Log Append",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Append median | {audit['append_median_us']:.1f} µs |",
        f"| Append p99 | {audit['append_p99_us']:.1f} µs |",
        f"| Total entries | {audit['total_entries']} |",
        "",
        "---",
        "",
        "*All benchmarks use `time.perf_counter()`. "
        "Medians over stated iteration counts.*",
        "",
    ]
    return "\n".join(lines)


# ─── Main ─────────────────────────────────────────────────────────────

def main():
    import_json = "--json" in sys.argv

    print("Seal Benchmarks")
    print("=" * 50)

    print("[1/6] AES-256-GCM throughput …", end=" ", flush=True)
    aes_gcm = bench_cipher_throughput(CipherSuite.AES256_GCM)
    print("done")

    print("[2/6] ChaCha20-Poly1305 throughput …", end=" ", flush=True)
    chacha = bench_cipher_throughput(CipherSuite.CHACHA20_POLY1305)
    print("done")

    print("[3/6] PBKDF2 derivation (600K iter) …", end=" ", flush=True)
    kdf = bench_pbkdf2()
    print(f"{kdf['median_ms']:.0f} ms median")

    print("[4/6] DEK wrap/unwrap …", end=" ", flush=True)
    dek = bench_dek_wrap()
    print(f"{dek['total_median_us']:.1f} µs roundtrip")

    print("[5/6] Full save/load roundtrip …", end=" ", flush=True)
    rt = bench_roundtrip()
    print(f"{rt['roundtrip_median_ms']:.2f} ms roundtrip")

    print("[6/6] Audit log append …", end=" ", flush=True)
    audit = bench_audit_append()
    print(f"{audit['append_median_us']:.1f} µs median")

    print()
    meta = _metadata()

    md = _write_results_md(meta, aes_gcm, chacha, kdf, dek, rt, audit)
    results_path = ROOT / "benchmarks" / "RESULTS.md"
    results_path.write_text(md, encoding="utf-8")
    print(f"Results written to {results_path}")

    if import_json:
        blob = json.dumps({
            "metadata": meta,
            "aes_gcm": aes_gcm,
            "chacha20": chacha,
            "pbkdf2": kdf,
            "dek_wrap": dek,
            "roundtrip": rt,
            "audit_append": audit,
        }, indent=2)
        print(blob)


if __name__ == "__main__":
    main()
