# Seal — User Guide

Seal is a zero-cloud encrypted file vault with tamper-evident audit, canary detection, and compliance reports. It has three interfaces: **CLI**, **TUI** (terminal UI), and **GUI** (desktop window). All three operate on the same vault directory.

---

## Installation

### From source (development)

```bash
git clone <repo-url>
cd aegis-vault
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS/Linux
pip install -e ".[dev]"
```

### Standalone executable

Build with PyInstaller (requires `pip install pyinstaller`):

```bash
python packaging/build.py
```

Output: `packaging/dist/seal/seal.exe` (Windows) or `packaging/dist/seal/seal` (macOS/Linux).

No Python installation required on the target machine.

---

## Quick Start

### 1. Create a vault

```bash
seal init --path ./my-vault --passphrase "your-secret"
```

This creates a directory with:
```
my-vault/
  keys/
    manifest.enc    # encrypted DEK manifest
    audit.log       # tamper-evident audit chain
  .canaries/
    canaries.json   # canary file registry
```

### 2. Save data

```bash
# From a JSON string
seal save -n personal -i mypassword -d '{"username":"alice","password":"s3cret"}'

# From a file
echo '{"api_key":"abc123"}' > config.json
seal save -n work -i api-config -f config.json
```

### 3. Load data

```bash
seal load -n personal -i mypassword
seal load -n personal -i mypassword -F json    # JSON output
seal load -n personal -i mypassword -F text    # plain text
```

### 4. List items

```bash
seal list                    # all namespaces
seal list -n personal        # specific namespace
seal list -F json            # JSON output
```

### 5. Delete items

```bash
seal delete -n personal -i mypassword -y    # skip confirmation
seal delete -n personal -i mypassword       # prompts for confirmation
```

### 6. Verify integrity

```bash
seal verify                  # audit chain + canary status
seal verify -F json          # machine-readable output
```

---

## CLI Reference

Global options (before any command):

| Option | Description |
|--------|-------------|
| `--path, -P` | Vault directory (or set `SEAL_VAULT` env var) |
| `--passphrase, -p` | Master passphrase (or set `SEAL_PASSPHRASE` env var) |
| `--version` | Show version |
| `--help` | Show help |

### `seal init`

Create a new encrypted vault.

```bash
seal init --path ./my-vault --passphrase "secret"
seal init -P ./my-vault -p "secret" --cipher chacha20
```

| Option | Values | Default |
|--------|--------|---------|
| `--path, -P` | directory path | *required* |
| `--passphrase, -p` | text | *prompted* |
| `--cipher` | `aes-gcm`, `chacha20` | `aes-gcm` |

### `seal save`

Save data to the vault.

```bash
seal save -n personal -i doc1 -d '{"key":"value"}'
seal save -n work -i config -f config.json
```

| Option | Description |
|--------|-------------|
| `-n, --ns` | Namespace: `personal`, `work`, `archive` |
| `-i, --id` | Item identifier |
| `-d, --data` | JSON data string |
| `-f, --file` | Read JSON from file |

### `seal load`

Load data from the vault.

```bash
seal load -n personal -i doc1
seal load -n personal -i doc1 -F json
```

| Option | Values | Default |
|--------|--------|---------|
| `-n, --ns` | namespace | *required* |
| `-i, --id` | item id | *required* |
| `-F, --format` | `text`, `json`, `markdown` | `json` |

### `seal list`

List items in the vault.

```bash
seal list
seal list -n personal
seal list -F json
```

### `seal delete`

Delete an item from the vault.

```bash
seal delete -n personal -i doc1 -y
seal delete -n personal -i doc1
```

| Option | Description |
|--------|-------------|
| `-y, --yes` | Skip confirmation prompt |

### `seal verify`

Verify vault integrity — audit log chain + canary status.

```bash
seal verify
seal verify -F json
```

Output includes:
- **Audit Chain**: VALID or BROKEN (SHA-256 chain integrity)
- **Canary Status**: CLEAN or N TRIGGERED (ransomware detection)

### `seal canary`

Ransomware canary operations.

```bash
seal canary deploy                    # deploy default 6 decoy files
seal canary deploy --names "fakes.xlsx,fakes.pdf"  # custom names
seal canary check                     # check all canaries for tampering
seal canary remove                    # remove all canary files
```

Canary files are placed in your `~/Documents`, `~/Desktop`, and vault directory. They look like real sensitive files (`passwords.xlsx`, `financials.pdf`, etc.) but contain random data. If a ransomware process modifies them, Seal detects the entropy change.

### `seal report`

Generate compliance reports.

```bash
seal report generate -f soc2
seal report generate -f hipaa -F markdown
seal report generate -f gdpr -F json
seal report generate -f iso27001
```

| Framework | Full Name |
|-----------|-----------|
| `soc2` | SOC 2 Type II |
| `hipaa` | HIPAA Security Rule |
| `gdpr` | GDPR (General Data Protection Regulation) |
| `iso27001` | ISO/IEC 27001:2022 |

### `seal share`

Multi-user key exchange.

```bash
seal share add -u <recipient-pubkey-hex> -d <dek-hex>
seal share list
seal share remove -u <user-id>
```

### `seal tui`

Launch the interactive terminal UI. See [TUI section](#tui-terminal-user-interface).

### `seal gui`

Launch the desktop GUI. See [GUI section](#gui-desktop-application).

### `seal version`

```bash
seal version
# seal 0.1.0
```

---

## TUI (Terminal User Interface)

The TUI is a full-screen interactive vault browser built with [Textual](https://textual.textualize.io/).

### Launch

```bash
seal tui
seal tui --path ./my-vault
```

### Screens

#### 1. Login

On launch, you see a login screen. Enter your master passphrase and press Enter or click **Unlock**.

#### 2. Vault Browser

After login, the vault browser shows:

- **Left panel**: Table of all entries (Namespace + Item columns)
- **Right panel**: Details of the selected entry (JSON formatted)
- **Top bar**: Search field for filtering
- **Bottom bar**: Status (entry count)

Click any row to view its contents.

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Q` | Quit |
| `Ctrl+V` | Verify vault integrity (audit + canary) |
| `Ctrl+G` | Open password generator |
| `Ctrl+F` | Focus search bar |
| `Escape` | Go back / close screen |

### Password Generator

Press `Ctrl+G` to open the password generator:

- Type a length (8–64) in the length field
- The generated password appears in the output field
- Click **Regenerate** for a new password
- Click **Copy to Clipboard** (requires `pyperclip`)

### Verify Integrity

Press `Ctrl+V` to check:
- Audit log chain integrity (SHA-256 verification)
- Canary file status (entropy-based tamper detection)

Results appear as a notification toast.

---

## GUI (Desktop Application)

The GUI is a tkinter desktop window with a tree view, entry form, and password generator.

### Launch

```bash
seal gui
seal gui --path ./my-vault
```

### Login Dialog

On launch, a login dialog appears. Enter your passphrase and click **OK**.

### Main Window

The main window has:

- **Tree view** (left): Hierarchical view of namespaces and entries
- **Entry form** (right): View/edit selected entry as JSON
- **Menu bar**: File, Tools, Help menus

### Menu Actions

| Menu | Action | Description |
|------|--------|-------------|
| File → New Entry | `Ctrl+N` | Add a new entry |
| File → Refresh | `Ctrl+R` | Reload vault contents |
| File → Exit | `Ctrl+Q` | Close application |
| Tools → Verify | — | Check audit chain + canary status |
| Tools → Generate Password | `Ctrl+G` | Open password generator |
| Tools → Deploy Canaries | — | Deploy ransomware decoy files |
| Help → About | — | Show version info |

### Password Generator

Opens a dialog with:
- Length slider (8–64)
- Generated password display
- Copy to clipboard button
- Regenerate button

---

## Python API

Use Seal as a library in your own Python code.

### AegisVault

```python
from aegis import AegisVault

# Create or open a vault
vault = AegisVault("./my-vault", "your-passphrase")

# Save data
vault.save("personal", "doc1", {"username": "alice", "password": "s3cret"})

# Load data
data = vault.load("personal", "doc1")
print(data)  # {"username": "alice", "password": "s3cret"}

# List items
items = vault.list_items("personal")
print(items)  # ["doc1"]

# Delete items
vault.delete("personal", "doc1")
```

### AuditLog

```python
from aegis import AuditLog

log = AuditLog("./my-vault")
log.append("save", "personal", "doc1")    # append an entry
valid = log.verify()                       # verify chain integrity
entries = log.get_entries(namespace="personal")  # filter entries
print(log.entry_count)                     # number of entries
```

### CanaryManager

```python
from aegis import CanaryManager

mgr = CanaryManager("./my-vault")
created = mgr.deploy()                     # deploy decoy files
triggered = mgr.check_all()                # check for tampering
removed = mgr.remove()                     # remove all canaries
```

### ComplianceReport

```python
from aegis import AuditLog, ComplianceReport

log = AuditLog("./my-vault")
report = ComplianceReport(log)

result = report.generate("soc2")           # dict with controls + summary
md = report.export_markdown("hipaa")       # markdown string
json_str = report.export_json("gdpr")      # JSON string
```

### ShareManager

```python
from aegis import ShareManager

sm = ShareManager("./my-vault")
user_id, pub_hex = sm.generate_keypair()   # generate X25519 keypair
sm.share_vault(user_id, pub_hex, dek)      # share vault with user
users = sm.list_users()                    # list shared users
sm.unshare_vault(user_id)                  # revoke access
```

---

## Namespaces

| Namespace | Purpose |
|-----------|---------|
| `personal` | Personal documents, passwords, notes |
| `work` | Work-related files, configs, API keys |
| `archive` | Long-term storage, backups |

All three are created when you initialize a vault. Items are isolated by namespace — AAD binding prevents cross-namespace file swaps.

---

## Security

- **Your passphrase never leaves your machine.** No network calls, no telemetry.
- **Envelope encryption**: Each item gets its own Data Encryption Key (DEK). DEKs are wrapped under a Master Key derived from your passphrase via PBKDF2-HMAC-SHA256 (600K iterations).
- **Tamper-evident audit log**: Every operation is appended to a SHA-256 chained log. Modifying any entry breaks the chain.
- **Canary detection**: Decoy files with known entropy. Ransomware that encrypts them triggers an alert.
- **Atomic writes**: All writes use `.tmp → fsync → os.replace` to prevent corruption on crash.
- **Secure deletion**: Files are overwritten with random bytes before deletion.

---

## Troubleshooting

### "Error: Decryption failed"

Wrong passphrase or corrupted file. Verify you're using the correct passphrase.

### "Error: Item not found"

The item doesn't exist in the specified namespace. Run `seal list -n <namespace>` to see available items.

### TUI doesn't launch

Ensure you're in a real terminal (Windows Terminal, PowerShell, not VS Code integrated terminal). Textual requires a proper terminal emulator.

### GUI doesn't launch

Ensure you have a display server running. On Windows, this works out of the box. On Linux, you may need `python3-tk` installed.

### Canary false positives

If canary files are modified by legitimate software (antivirus scans, file syncing), re-deploy them:

```bash
seal canary remove
seal canary deploy
```
