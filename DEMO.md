# Seal — Command Reference

Quick reference for every CLI command and TUI shortcut.

---

## Global Options

Available on all commands:

| Option | Description |
|--------|-------------|
| `-P, --path` | Vault directory (or `SEAL_VAULT` env var) |
| `-p, --passphrase` | Master passphrase (or `SEAL_PASSPHRASE` env var) |
| `--help` | Show help |
| `--version` | Show version |

---

## Create a Vault

```bash
seal init -P ./my-vault
seal init -P ./my-vault -p "my-secret" --cipher chacha20
```

| Option | Values | Default |
|--------|--------|---------|
| `-P, --path` | directory path | **required** |
| `-p, --passphrase` | text | prompted |
| `--cipher` | `aes-gcm`, `chacha20` | `aes-gcm` |

---

## Save Data

```bash
# Key=value pairs (easiest — no quoting needed)
seal save -P ./my-vault -n personal -i gmail --kv user=alice --kv pass=s3cret

# JSON string
seal save -P ./my-vault -n personal -i gmail -d '{"user":"alice","pass":"s3cret"}'

# Read JSON from file (avoids shell quoting issues)
seal save -P ./my-vault -n personal -i gmail -d @config.json

# Read from file handle
seal save -P ./my-vault -n personal -i config -f config.json

# Interactive mode (prompts for each field)
seal save -P ./my-vault -n personal -i gmail --interactive
```

| Option | Description |
|--------|-------------|
| `-P, --path` | Vault directory |
| `-p, --passphrase` | Master passphrase |
| `-n, --ns` | Namespace: `personal`, `work`, `archive` |
| `-i, --id` | Item identifier |
| `-d, --data` | JSON string or `@filename` |
| `-f, --file` | Read JSON from file handle |
| `--kv` | Key=value pair (repeatable) |
| `-I, --interactive` | Enter fields interactively |

---

## Load Data

```bash
seal load -P ./my-vault -n personal -i gmail
seal load -P ./my-vault -n personal -i gmail -F json
seal load -P ./my-vault -n personal -i gmail -F text
seal load -P ./my-vault -n personal -i gmail -F markdown
seal load -P ./my-vault -n personal -i gmail --clip
```

| Option | Values | Default |
|--------|--------|---------|
| `-P, --path` | vault directory | cwd |
| `-p, --passphrase` | master passphrase | prompted |
| `-n, --ns` | namespace | **required** |
| `-i, --id` | item id | **required** |
| `-F, --format` | `text`, `json`, `markdown` | `json` |
| `-c, --clip` | copy first value to clipboard (auto-clears 30s) | off |

---

## List Items

```bash
seal list -P ./my-vault
seal list -P ./my-vault -n personal
seal list -P ./my-vault --long
seal list -P ./my-vault -F json
```

| Option | Values | Default |
|--------|--------|---------|
| `-P, --path` | vault directory | cwd |
| `-p, --passphrase` | master passphrase | prompted |
| `-n, --ns` | namespace (omit for all) | all |
| `-F, --format` | `text`, `json` | `text` |
| `-l, --long` | show creation dates | off |

---

## Delete Items

```bash
seal delete -P ./my-vault -n personal -i gmail -y
seal delete -P ./my-vault -n personal -i gmail
```

| Option | Description |
|--------|-------------|
| `-P, --path` | Vault directory |
| `-p, --passphrase` | Master passphrase |
| `-n, --ns` | Namespace |
| `-i, --id` | Item identifier |
| `-y, --yes` | Skip confirmation prompt |

---

## Verify Integrity

```bash
seal verify -P ./my-vault
seal verify -P ./my-vault -F json
```

Checks audit log chain (SHA-256) and canary file status.

---

## Canary Detection

```bash
# Deploy decoy files (passwords.xlsx, financials.pdf, etc.)
seal canary deploy -P ./my-vault
seal canary deploy -P ./my-vault --names "fake.xlsx,fake.pdf"
seal canary deploy -P ./my-vault -y    # skip confirmation

# Check for tampering
seal canary check -P ./my-vault

# Remove all canary files
seal canary remove -P ./my-vault
```

---

## Compliance Reports

```bash
seal report generate -P ./my-vault -f soc2
seal report generate -P ./my-vault -f hipaa -F markdown
seal report generate -P ./my-vault -f gdpr -F json
seal report generate -P ./my-vault -f iso27001
```

| Framework | Full Name |
|-----------|-----------|
| `soc2` | SOC 2 Type II |
| `hipaa` | HIPAA Security Rule |
| `gdpr` | GDPR |
| `iso27001` | ISO/IEC 27001:2022 |

---

## Multi-User Sharing

```bash
# Generate a keypair
seal keygen

# Share vault with another user
seal share add -P ./my-vault -u <recipient-pubkey-hex> -d <dek-hex>

# List users with access
seal share list -P ./my-vault

# Revoke access
seal share remove -P ./my-vault -u <user-id>
```

---

## Password Generator (CLI)

```bash
seal generate
seal generate -l 32
seal generate -l 16 --no-symbols -n 5
seal generate --clip
```

| Option | Description | Default |
|--------|-------------|---------|
| `-l, --length` | Password length | 20 |
| `--no-symbols` | Exclude special characters | off |
| `-n, --count` | Number of passwords | 1 |
| `-c, --clip` | Copy to clipboard (auto-clears 30s) | off |

---

## Doctor (Health Check)

```bash
seal doctor -P ./my-vault
```

Checks: vault directory, keys directory, manifest, audit log chain, canary status.

---

## TUI (Terminal UI)

```bash
seal tui -P ./my-vault
```

### Login Screen

- Type passphrase, press Enter or click **Unlock**
- **Windows Hello**: Click **Unlock with Windows Hello** (if configured)
- **Save passphrase**: Click **Save passphrase for next time** to store in Windows Hello

### Vault Browser

| Key | Action |
|-----|--------|
| `Ctrl+N` | New entry |
| `Ctrl+E` | Edit selected entry |
| `Ctrl+D` | Delete selected entry |
| `Ctrl+F` | Focus search bar |
| `Ctrl+G` | Password generator |
| `Ctrl+V` | Verify integrity |
| `Ctrl+Q` | Quit |
| `Escape` | Go back / close |

### New Entry (`Ctrl+N`)

1. Select namespace from dropdown
2. Enter item ID (e.g. `gmail`, `wifi-home`)
3. Add key-value pairs with **+ Add Field**
4. Click **Save**

### Password Generator (`Ctrl+G`)

- Set length (8–64)
- **Copy to Clipboard** — auto-clears after 30s
- Strength meter shows entropy bits

---

## Python API

```python
from aegis import AegisVault, AuditLog, CanaryManager, ComplianceReport, ShareManager

# Vault
vault = AegisVault("./my-vault", "passphrase")
vault.save("personal", "doc1", {"key": "value"})
data = vault.load("personal", "doc1")
items = vault.list_items("personal")
vault.delete("personal", "doc1")

# Audit
log = AuditLog("./my-vault")
valid = log.verify()
log.append("save", "personal", "doc1")

# Canary
mgr = CanaryManager("./my-vault")
mgr.deploy()
triggered = mgr.check_all()

# Compliance
rpt = ComplianceReport(log)
rpt.generate("soc2")
rpt.export_markdown("hipaa")

# Sharing
sm = ShareManager("./my-vault")
user_id, pub_hex = sm.generate_keypair()
sm.share_vault(user_id, pub_hex, dek)
```

---

## Environment Variables

| Variable | Equivalent |
|----------|-----------|
| `SEAL_VAULT` | `--path` |
| `SEAL_PASSPHRASE` | `--passphrase` |

---

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `Decryption failed` | Wrong passphrase | Re-enter correct passphrase |
| `Item not found` | Item doesn't exist | `seal list -n <ns>` to check |
| TUI black screen | Old terminal | Use Windows Terminal or VS Code terminal |
| `No module named 'pyperclip'` | Clipboard not installed | `pip install pyperclip` |
