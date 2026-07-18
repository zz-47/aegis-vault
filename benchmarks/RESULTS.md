# Seal — Benchmark Results

*Generated 2026-07-19 02:45:18*  
Platform: `Windows-11-10.0.26200-SP0` · Python 3.14.2 · cryptography 49.0.0 · AMD64

---

## 1. AEAD Cipher Throughput

### AES-256-GCM

| Size | Encrypt (µs) | Decrypt (µs) | Enc MB/s | Dec MB/s |
|------|-------------|-------------|----------|----------|
| 64B | 3.3 | 3.0 | 18.5 | 20.3 |
| 256B | 3.3 | 3.0 | 74.0 | 81.4 |
| 1KB | 3.7 | 3.4 | 263.9 | 287.2 |
| 4KB | 4.7 | 4.3 | 831.1 | 908.4 |
| 64KB | 24.3 | 22.8 | 2572.0 | 2741.2 |
| 256KB | 226.2 | 225.6 | 1105.2 | 1108.4 |
| 1MB | 839.4 | 839.0 | 1191.4 | 1191.9 |

### ChaCha20-Poly1305

| Size | Encrypt (µs) | Decrypt (µs) | Enc MB/s | Dec MB/s |
|------|-------------|-------------|----------|----------|
| 64B | 3.5 | 3.1 | 17.4 | 19.7 |
| 256B | 3.5 | 3.2 | 69.8 | 76.3 |
| 1KB | 4.0 | 3.6 | 244.1 | 271.3 |
| 4KB | 5.8 | 5.5 | 673.5 | 710.2 |
| 64KB | 40.8 | 40.7 | 1531.9 | 1535.6 |
| 256KB | 525.7 | 523.7 | 475.6 | 477.3 |
| 1MB | 3030.8 | 2979.4 | 329.9 | 335.6 |

---

## 2. PBKDF2 Key Derivation (SHA-256, 600K iterations)

| Metric | Value |
|--------|-------|
| Median | 523.8 ms |
| Min | 348.0 ms |
| Max | 723.6 ms |

---

## 3. DEK Wrap / Unwrap (AES-GCM envelope)

| Metric | Value |
|--------|-------|
| Wrap median | 18.6 µs |
| Unwrap median | 20.2 µs |
| Total roundtrip | 38.7 µs |

---

## 4. Full Save → Load Roundtrip

| Metric | Value |
|--------|-------|
| Save median | 16.72 ms |
| Load median | 19.34 ms |
| Roundtrip median | 36.06 ms |
| Iterations | 100 |

---

## 5. Audit Log Append

| Metric | Value |
|--------|-------|
| Append median | 16403.2 µs |
| Append p99 | 34845.0 µs |
| Total entries | 1000 |

---

*All benchmarks use `time.perf_counter()`. Medians over stated iteration counts.*
