# Seal — Command Reference

Quick reference for every CLI command, TUI screen, and Python API method.

---

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Create a vault
seal init -P ./my-vault -p "my-secret"

# Save something
seal save -P ./my-vault -n personal -i gmail --kv user=alice --kv pass=s3cret

# Load it back
seal load -P ./my-vault -n personal -i gmail

# Open TUI
seal tui -P ./my-vault
```

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

## Find Vaults on Disk

Seal doesn't track a global vault registry. A vault is any directory containing `keys/manifest.enc`. Find them with:

```powershell
# Windows (PowerShell)
Get-ChildItem -Path C:\Users\YOU -Recurse -Filter "manifest.enc" -ErrorAction SilentlyContinue | Select-Object FullName

# Or find vault directories specifically
Get-ChildItem -Path C:\Users\YOU\Documents -Recurse -Directory -Filter "keys" -ErrorAction SilentlyContinue | Where-Object { Test-Path "$($_.FullName)\manifest.enc" } | Select-Object FullName

# macOS / Linux
find ~ -name "manifest.enc" 2>/dev/null
```

---

## Save Data

```bash
# Key=value pairs (easiest — no quoting needed on any shell)
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

### Key-Value Pairs

When you save data, you're storing a **dictionary** — named fields with values.

| Key | Value |
|-----|-------|
| `user` | `alice@gmail.com` |
| `pass` | `s3cretPassword123` |
| `recovery` | `backup@protonmail.com` |
| `2fa_secret` | `JBSWY3DPEHPK3PXP` |

Keys and values are strings. You decide what they mean. Seal encrypts whatever dictionary you give it.

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
seal list -P ./my-vault                    # all namespaces
seal list -P ./my-vault -n personal        # one namespace
seal list -P ./my-vault --long             # with creation dates
seal list -P ./my-vault -F json            # JSON output
```

Output:
```
personal/
  gmail
  wifi-home

work/
  api-config

archive/
  (empty)
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
seal delete -P ./my-vault -n personal -i gmail -y    # skip confirmation
seal delete -P ./my-vault -n personal -i gmail       # prompts first
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

Checks:
- **Audit log chain** — SHA-256 verification of append-only log
- **Canary status** — whether decoy files have been modified

---

## Canary Detection

Seal places fake files (`passwords.xlsx`, `financials.pdf`, etc.) in your vault directory, `~/Documents`, and `~/Desktop`. If ransomware encrypts your real files, it encrypts these decoys first. Seal detects the change.

```bash
# Deploy 6 decoy files to vault, ~/Documents, ~/Desktop
seal canary deploy -P ./my-vault
seal canary deploy -P ./my-vault --names "fake.xlsx,fake.pdf"
seal canary deploy -P ./my-vault -y

# Check for tampering
seal canary check -P ./my-vault

# Remove all canary files
seal canary remove -P ./my-vault
```

### How Detection Works

1. Each canary file is 512 bytes of cryptographic random data
2. At deploy time, SHA-256 hash is stored in `.canaries/canaries.json`
3. On check, current file is re-hashed and compared to original
4. Hash mismatch = tampering detected → alert

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

Reports map your vault's audit log to compliance framework controls and show which controls your usage satisfies.

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

## Password Generator

### CLI

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

### TUI (`Ctrl+G`)

- Set length (8–64) — password regenerates as you type
- Strength meter: WEAK → FAIR → STRONG → VERY STRONG
- **Copy to Clipboard** — auto-clears after 30s
- **Regenerate** — new random password

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

### Screen 1: Login

```
┌─────────────────────────────────┐
│       Seal — Local Vault        │
│  Enter your master passphrase   │
│  ┌───────────────────────────┐  │
│  │ ●●●●●●●●●●               │  │
│  └───────────────────────────┘  │
│  [Unlock]                       │
│  [Save passphrase for next time]│
└─────────────────────────────────┘
```

- Type passphrase, press **Enter** or click **Unlock**
- **Windows Hello**: Click **Unlock with Windows Hello** (if configured)
- **Save passphrase**: Stores in Windows Hello for biometric unlock next time

### Screen 2: Vault Browser

```
 Search entries...                     ┌──────────────────────┐
 [New] [Edit] [Delete]                │  Select an entry     │
┌──────────────┬───────────────────────┤                      │
│ Namespace    │ Item                  │  {                   │
│ personal     │ gmail                 │    "user": "alice",  │
│ personal     │ wifi-home             │    "pass": "s3cret"  │
│ work         │ api-config            │  }                   │
├──────────────┴───────────────────────┤                      │
│ 3 entries loaded                     │                      │
└──────────────────────────────────────┴──────────────────────┘
```

**Left panel**: Table of all entries (click a row to view)
**Right panel**: Decrypted JSON of selected entry
**Top**: Search bar (type to filter)
**Bottom**: Status bar with keyboard shortcuts

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl+N` | Create new entry |
| `Ctrl+E` | Edit selected entry |
| `Ctrl+D` | Delete selected entry |
| `Ctrl+F` | Jump to search bar |
| `Ctrl+G` | Open password generator |
| `Ctrl+R` | Open compliance report |
| `Ctrl+Y` | Open canary management |
| `Ctrl+V` | Quick verify (audit + canary) |
| `Ctrl+Q` | Quit |
| `Escape` | Go back / close screen |

### Screen 3: New Entry (`Ctrl+N`)

```
┌─────────────────────────────────┐
│ New Entry                       │
│ Namespace: [personal ▾]         │
│ Item ID:   [gmail           ]   │
│ Key-value pairs:                │
│ ┌───────┐ ┌────────────┐ ┌──┐  │
│ │ Key   │ │ Value      │ │X │  │
│ └───────┘ └────────────┘ └──┘  │
│ + Add Field                     │
│ [Save]                          │
└─────────────────────────────────┘
```

1. Pick namespace from dropdown
2. Type item name (e.g. `gmail`)
3. Fill key-value pairs (e.g. `user` = `alice@gmail.com`)
4. Click **+ Add Field** for more rows, **X** to remove
5. Click **Save**

### Screen 4: Edit Entry (`Ctrl+E`)

Select an entry in the table, press `Ctrl+E` to edit its raw JSON. Modify and click **Save**.

### Screen 5: Password Generator (`Ctrl+G`)

```
┌─────────────────────────────────┐
│ Password Generator              │
│ Length:                          │
│ [20         ]                   │
│ [xK9#mP2vLqR5nW8jYt4f]         │
│ STRONG  (119 bits of entropy)   │
│ [Copy to Clipboard] [Regenerate]│
└─────────────────────────────────┘
```

- Change length (8–64) — password regenerates automatically
- **Copy to Clipboard** — auto-clears after 30s
- **Regenerate** — new random password

### Screen 6: Compliance Report (`Ctrl+R`)

```
 Compliance Report
 Framework: [SOC 2 Type II ▾]
┌─────────────────────────────────────────────────┐
│ Control  │ Status    │ Evidence                  │
│ CC6.1    │ COMPLIANT │ 5                        │
│ CC6.6    │ COMPLIANT │ 3                        │
│ CC7.2    │ NO_DATA   │ 0                        │
├─────────────────────────────────────────────────┤
│ 3/4 controls compliant                          │
│                                                 │
│ [Export JSON] [Export Markdown]                  │
└─────────────────────────────────────────────────┘
```

1. Select framework from dropdown
2. Controls table shows compliance status
3. Export buttons output JSON or Markdown

### Screen 7: Canary Management (`Ctrl+Y`)

```
 Canary Management
┌─────────────────────────────────────────────────┐
│ Name                  Path              Status   │
│ passwords.xlsx        ~/Documents/...   OK      │
│ financials.pdf        ~/Desktop/...     OK      │
│ backup_keys.pem       ~/Documents/...   MISSING │
├─────────────────────────────────────────────────┤
│ [Deploy] [Check Now] [Remove All]               │
└─────────────────────────────────────────────────┘
```

- **Deploy** — create decoy files in vault, ~/Documents, ~/Desktop
- **Check Now** — scan all canaries for tampering
- **Remove All** — delete all canary files

---

## What the TUI Can't Do (use CLI instead)

| Task | CLI Command |
|------|------------|
| Create a vault | `seal init -P ./vault` |
| Share vault access | `seal share add ...` |
| Generate keypairs | `seal keygen` |
| Run health diagnostics | `seal doctor -P ./vault` |

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
removed = mgr.remove()

# Compliance
rpt = ComplianceReport(log)
result = rpt.generate("soc2")
md = rpt.export_markdown("hipaa")
json_str = rpt.export_json("gdpr")

# Sharing
sm = ShareManager("./my-vault")
user_id, pub_hex = sm.generate_keypair()
sm.share_vault(user_id, pub_hex, dek)
users = sm.list_users()
sm.unshare_vault(user_id)
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
| TUI black screen | Terminal doesn't support VT100 | Use Windows Terminal or VS Code terminal |
| `No module named 'pyperclip'` | Clipboard not installed | `pip install pyperclip` |
| `No module named 'textual'` | Wrong Python / venv not active | Activate venv: `.venv\Scripts\Activate.ps1` |
