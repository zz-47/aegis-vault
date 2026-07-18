# Seal — Local Vault

**Zero-cloud encrypted file storage with tamper-evident audit, canary detection, and compliance reports.**

Your passphrase never leaves your machine. No cloud. No subscription. No telemetry.

---

## Services

Seal is open source. The following services are available for teams and organizations that need production support:

| Service | What You Get |
|---------|-------------|
| **On-Prem Deployment** | Seal installed, configured, and hardened in your infrastructure |
| **Compliance Audit** | Audit-ready reports (SOC 2, HIPAA, GDPR, ISO 27001) with documentation |
| **Custom Integrations** | Active Directory, LDAP, key rotation, SIEM piping — built to your requirements |
| **Security Review** | Full code audit and threat model walkthrough for your environment |
| **Support & Maintenance** | Updates, incident response, and ongoing hardening |

Every deployment is different. Seal will be tailored to fit your specific infrastructure, compliance requirements, and security policies — not a generic one-size-fits-all setup. Free evaluation. No lock-in. The audit log is free and open. [Reach out](#) to discuss your setup.

## Features

- **Envelope encryption** — Per-file DEKs wrapped under PBKDF2-derived Master Key
- **Tamper-evident audit log** — SHA-256 chained append-only log
- **Ransomware canary detection** — Decoy files with entropy-based monitoring
- **Compliance reports** — One-click SOC 2, HIPAA, GDPR, ISO 27001
- **Biometric unlock** — Windows Hello fingerprint via keyring
- **Multi-user key exchange** — X25519 stanzas for shared vaults
- **Atomic writes** — Crash-safe .tmp → fsync → os.replace pattern
- **Secure deletion** — Random overwrite before unlink

## Why Seal Exists

Seal was built as a personal effort to solve a few problems I kept running into with existing tools. It is designed for **solo deployment** — one person, one machine, one vault. The open-source tools listed below are all excellent and battle-tested at what they do. Seal does not try to replace any of them. It simply explores a combination of features I could not find in one place:

| Capability | Seal | Hashicorp Vault | VeraCrypt | Cryptomator | age | restic |
|-----------|------|----------------|-----------|-------------|-----|--------|
| Tamper-evident audit log | Free, open | Audit backend | - | - | - | Snapshot metadata |
| Ransomware canary detection | Entropy-based decoys | - | - | - | - | - |
| One-click compliance reports | Free, open | Enterprise add-on | - | - | - | - |
| Biometric unlock | Windows Hello | - | - | - | - | - |
| Multi-user key exchange | X25519 stanzas | Token / ACL system | - | - | X25519 stanzas | - |
| Zero cloud / zero server | Yes | Self-hosted option | Yes | Yes | Yes | Depends on backend |
| Envelope encryption (per-file DEK) | Yes | Transit engine | - | Yes | - | - |

Each tool makes different tradeoffs for good reasons. Hashicorp Vault is the standard for enterprise secrets management at scale. VeraCrypt has decades of battle-tested full-disk encryption. Cryptomator and restic solve cloud-backed storage elegantly. Seal explores the space where **local encrypted storage, tamper-evident logging, and compliance reporting meet in a single zero-server package**.

### Boundaries

Seal is an open-source demonstration of these concepts and may lack the high-tier features, hardening, and support that come with professional services. It is available under the **Business Source License 1.1 (BSL 1.1)**, which allows free evaluation and development use. **Production deployment requires a written license from the creator.** The source converts to an open-source license after the change date.

The creator is open to **business audits, security reviews, and tailored deployments** for organizations that need these capabilities in production. If you are exploring on-premise encryption for your team, reach out.

## Interfaces

Seal has three interfaces that all operate on the same vault:

| Interface | Launch | Best for |
|-----------|--------|----------|
| **CLI** | `seal save`, `seal load`, etc. | Scripting, automation, quick operations |
| **TUI** | `seal tui` | Interactive browsing, searching, password generation |
| **GUI** | `seal gui` | Desktop users, visual vault management |

See [docs/USER_GUIDE.md](docs/USER_GUIDE.md) for complete usage instructions.

## What It Does

```
Your File → JSON serialize → Encrypt with DEK → Encrypt DEK with Master Key → Write .enc to disk
                                                        ↑
                                              Derived from your passphrase
                                              via PBKDF2-HMAC-SHA256 (600K iterations)
```

Each file gets its own Data Encryption Key (DEK). The DEK is wrapped under a Master Key derived from your passphrase. The Master Key never touches disk — only the wrapped DEKs do. The entire manifest (mapping files to DEKs) is itself encrypted.

## Security Properties

| Property | Guarantee |
|----------|-----------|
| **At-rest encryption** | AES-256-GCM or ChaCha20-Poly1305 (auto-selected) |
| **Key derivation** | PBKDF2-HMAC-SHA256, 600K iterations (OWASP 2023 minimum) |
| **Envelope encryption** | Per-file DEK wrapped under Master Key |
| **Tamper detection** | AEAD auth tags on every blob |
| **Atomic writes** | .tmp → fsync → os.replace (crash-safe) |
| **Secure deletion** | Overwrite with random bytes before unlink |
| **Namespace isolation** | AAD binding prevents cross-namespace file swaps |

## Quick Start

```bash
# Install from source
pip install -e ".[dev]"

# Initialize a vault
seal init --path ./my-vault --passphrase "your-secret"

# Save data
seal save -n personal -i doc1 -d '{"username":"alice","password":"s3cret"}'

# Load it back
seal load -n personal -i doc1

# List items
seal list -n personal

# Verify integrity
seal verify

# Launch TUI (interactive terminal browser)
seal tui

# Launch GUI (desktop window)
seal gui
```

See [docs/USER_GUIDE.md](docs/USER_GUIDE.md) for the full reference covering all CLI commands, TUI, GUI, and Python API.

## Docker

```bash
docker build -t aegis-vault .
docker run -v $(pwd)/vault:/vault aegis-vault init --passphrase "secret" --vault /vault
```

## Python API

```python
from aegis.crypt_storage import AegisVault

vault = AegisVault("./my-vault", "your-passphrase")
vault.save("personal", "doc1", {"content": "secret data", "type": "note"})
data = vault.load("personal", "doc1")
```

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     AegisVault                            │
│              (save / load / delete / list)                │
├────────────────────┬──────────────────┬──────────────────┤
│     audit.py       │    canary.py     │    sharing.py    │
│  SHA-256 chain     │  Decoy files     │  X25519 stanzas  │
│  append-only log   │  Entropy monitor │  Multi-user DEK  │
├────────────────────┴──────────────────┴──────────────────┤
│                   KeyManager                              │
│           PBKDF2 → DEK wrap/unwrap → manifest             │
├──────────────────────────────────────────────────────────┤
│                    AeadCipher                             │
│          AES-256-GCM / ChaCha20-Poly1305                  │
└──────────────────────────────────────────────────────────┘
```

## Namespaces

| Namespace | Purpose |
|-----------|---------|
| `personal` | Personal documents, notes |
| `work` | Work-related files |
| `archive` | Long-term storage |

## Testing

144 tests across 12 test files covering encryption, key management, storage, audit, canary detection, sharing, biometric, compliance reports, CLI integration, atomic writes, data leak prevention, and attack/robustness scenarios.

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all 144 tests
python -m pytest tests/ -v

# Run a specific test module
python -m pytest tests/test_cipher.py -v

# Run a single test
python -m pytest tests/test_robustness.py::TestEdgeCases::test_unicode_data_roundtrip -v
```

See [tests/TEST_DOCUMENTATION.md](tests/TEST_DOCUMENTATION.md) for the full indexed test catalog with explanations for every test case.

## Benchmarks

Run benchmarks on your hardware:

```bash
python benchmarks/bench_cipher.py
```

## Research

See [docs/IMPLEMENTATION_PAPER.md](docs/IMPLEMENTATION_PAPER.md) for the security analysis.
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full module reference.
See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the threat model and adversarial assumptions.

## License

Seal is licensed under the **Business Source License 1.1 (BSL 1.1)**.

- **Evaluation & development use** — Free, no restrictions
- **Production deployment** — Requires a written license from the Licensor
- **Converts to open source** after the change date

See [LICENSE](LICENSE) for full terms.
