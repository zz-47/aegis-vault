# Seal — Benchmark Results

*Generated 2026-07-19 03:05:33*  
Platform: `Windows-11-10.0.26200-SP0` · Python 3.14.2 · cryptography 49.0.0 · AMD64

---

## 1. AEAD Cipher Throughput

### AES-256-GCM

| Size | Encrypt (µs) | Decrypt (µs) | Enc MB/s | Dec MB/s |
|------|-------------|-------------|----------|----------|
| 64B | 6.2 | 5.6 | 9.8 | 10.9 |
| 256B | 3.7 | 3.4 | 66.0 | 71.8 |
| 1KB | 6.0 | 5.4 | 162.8 | 180.8 |
| 4KB | 5.2 | 4.7 | 751.2 | 831.1 |
| 64KB | 19.8 | 19.0 | 3156.6 | 3289.5 |
| 256KB | 258.8 | 259.1 | 966.0 | 965.1 |
| 1MB | 1190.8 | 1162.1 | 839.8 | 860.5 |

### ChaCha20-Poly1305

| Size | Encrypt (µs) | Decrypt (µs) | Enc MB/s | Dec MB/s |
|------|-------------|-------------|----------|----------|
| 64B | 4.1 | 3.8 | 14.9 | 16.1 |
| 256B | 3.8 | 3.5 | 64.2 | 69.8 |
| 1KB | 4.5 | 4.1 | 217.0 | 238.2 |
| 4KB | 6.3 | 5.9 | 620.0 | 662.1 |
| 64KB | 41.7 | 41.2 | 1498.8 | 1517.0 |
| 256KB | 181.1 | 178.8 | 1380.1 | 1398.2 |
| 1MB | 1636.4 | 1646.1 | 611.1 | 607.5 |

---

## 2. PBKDF2 Key Derivation (SHA-256, 600K iterations)

| Metric | Value |
|--------|-------|
| Median | 352.3 ms |
| Min | 317.6 ms |
| Max | 512.1 ms |

---

## 3. DEK Wrap / Unwrap (AES-GCM envelope)

| Metric | Value |
|--------|-------|
| Wrap median | 4.9 µs |
| Unwrap median | 5.4 µs |
| Total roundtrip | 10.3 µs |

---

## 4. Full Save → Load Roundtrip

| Metric | Value |
|--------|-------|
| Save median | 12.45 ms |
| Load median | 14.09 ms |
| Roundtrip median | 26.54 ms |
| Iterations | 100 |

---

## 5. Audit Log Append

| Metric | Value |
|--------|-------|
| Append median | 7876.4 µs |
| Append p99 | 16134.8 µs |
| Total entries | 1000 |

---

*All benchmarks use `time.perf_counter()`. Medians over stated iteration counts.*
