# Changelog

All notable changes to Aegis Vault will be documented in this file.

## [0.1.0] - 2026-07-17

### Added
- Three-layer envelope encryption (cipher → key_manager → crypt_storage)
- AES-256-GCM and ChaCha20-Poly1305 dual-algorithm support
- PBKDF2-HMAC-SHA256 key derivation (600K iterations)
- Per-file Data Encryption Keys (DEKs) wrapped under Master Key
- Encrypted manifest with AAD domain separation
- Namespace-routed storage (personal, work, archive)
- Atomic writes (tmp → fsync → replace)
- Secure deletion (random overwrite before unlink)
- AAD-bound tamper detection
- FIFO DEK cache (128 entries)
- CLI interface (init, store, retrieve, list, delete)
- Benchmark suite (AES-GCM vs ChaCha20 throughput)
- Docker support
- 73 test cases
