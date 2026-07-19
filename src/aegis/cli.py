from __future__ import annotations

import functools
import hashlib
import json
import os
import sys
import time
from pathlib import Path

import rich_click as click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


# ─── Shared helpers ──────────────────────────────────────────────────

def _handle_errors(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            hint = getattr(e, "hint", "Check your command and try again.")
            console.print(Panel(
                f"[red bold]Error:[/] {e}\n[dim]{hint}[/]",
                title="[red]seal[/]",
                border_style="red",
            ))
            sys.exit(1)
    return wrapper


def _get_vault(ctx, path=None, passphrase=None):
    from aegis.crypt_storage import AegisVault
    if path:
        ctx.obj["path"] = Path(path)
    vault_path = ctx.obj.get("path") or Path.cwd()
    pw = passphrase or ctx.obj.get("passphrase")
    if not pw:
        pw = click.prompt("Passphrase", hide_input=True)
    return AegisVault(vault_path, pw)


def _resolve_path(ctx, path=None):
    if path:
        ctx.obj["path"] = Path(path)
    return ctx.obj.get("path") or Path.cwd()


def _check_passphrase_strength(passphrase: str) -> list[str]:
    warnings = []
    if len(passphrase) < 8:
        warnings.append("shorter than 8 characters")
    if len(passphrase) < 12:
        warnings.append("consider using 12+ characters for stronger security")
    if passphrase.lower() == passphrase and passphrase.isalpha():
        warnings.append("no uppercase letters or numbers")
    if passphrase.isalnum() and not any(ch in passphrase for ch in "!@#$%^&*()-_+=[]{}|;':\",./<>?"):
        warnings.append("no special characters")
    common = {"password", "123456", "qwerty", "letmein", "admin", "welcome"}
    if passphrase.lower() in common:
        warnings.append("this is a commonly used password — choose something unique")
    return warnings


# ─── Root Group ──────────────────────────────────────────────────────

@click.group()
@click.version_option(package_name="aegis-vault")
@click.option("--path", "-P", envvar="SEAL_VAULT", help="Vault directory path.", type=click.Path())
@click.option("--passphrase", "-p", envvar="SEAL_PASSPHRASE", help="Master passphrase.", hide_input=True)
@click.pass_context
def cli(ctx, path, passphrase):
    """Seal — Encrypted Password Vault

    Local password vault with encryption, tamper-evident audit log,
    ransomware detection, and compliance reports.

    Your passphrase never leaves your machine.

    \b
    Getting started:
      seal init -P ./my-vault       Create a new vault
      seal save -P ./my-vault ...   Store a password
      seal load -P ./my-vault ...   View a password
      seal list -P ./my-vault       List all saved items
    """
    ctx.ensure_object(dict)
    ctx.obj["path"] = Path(path) if path else None
    ctx.obj["passphrase"] = passphrase


# ─── init ────────────────────────────────────────────────────────────

@cli.command()
@click.option("--path", "-P", required=True, help="Directory to initialize as vault.", type=click.Path())
@click.option("--passphrase", "-p", prompt=True, hide_input=True, confirmation_prompt=True, help="Master passphrase.")
@click.option("--cipher", type=click.Choice(["aes-gcm", "chacha20"]), default="aes-gcm", help="Encryption algorithm.")
@click.pass_context
@_handle_errors
def init(ctx, path, passphrase, cipher):
    """Create a new encrypted vault.

    Namespaces organize your items into groups: personal, work, and archive.

    \b
    Examples:
      seal init --path ./my-vault
      seal init -P ./secrets -p "my-passphrase" --cipher chacha20
    """
    from aegis.crypt_storage import AegisVault

    warnings = _check_passphrase_strength(passphrase)
    if warnings:
        console.print(f"[yellow]Weak passphrase:[/] {'; '.join(warnings)}")

    vault = AegisVault(path, passphrase, cipher_suite=cipher)
    console.print(Panel(
        f"[green]Vault created at[/] {Path(path).resolve()}\n"
        f"[dim]Cipher: {cipher} | Namespaces: personal, work, archive[/]\n"
        f"[dim]Items are organized into namespaces (like folders).[/]",
        title="[green]seal init[/]",
        border_style="green",
    ))


# ─── save ────────────────────────────────────────────────────────────

@cli.command()
@click.option("--path", "-P", envvar="SEAL_VAULT", help="Vault directory path.", type=click.Path())
@click.option("--passphrase", "-p", envvar="SEAL_PASSPHRASE", help="Master passphrase.", hide_input=True)
@click.option("--ns", "-n", required=True, type=click.Choice(["personal", "work", "archive"]), help="Namespace (like a folder).")
@click.option("--id", "-i", "item_id", required=True, help="Item identifier.")
@click.option("--data", "-d", help='JSON string or @filename (prefix with @ to read from file).')
@click.option("--file", "-f", "infile", type=click.File("r"), help="Read JSON from file.")
@click.option("--kv", "kv_pairs", multiple=True, help="Key=value pair (repeatable). E.g. --kv user=alice --kv pass=s3cret")
@click.option("--interactive", "-I", is_flag=True, help="Enter fields interactively.")
@click.pass_context
@_handle_errors
def save(ctx, path, passphrase, ns, item_id, data, infile, kv_pairs, interactive):
    """Save data to the vault.

    \b
    Examples (pick any input method):
      seal save -P ./my-vault -n personal -i gmail --kv user=alice --kv pass=s3cret
      seal save -P ./my-vault -n personal -i gmail -d '{"password":"abc"}'
      seal save -P ./my-vault -n personal -i gmail -d @config.json
      seal save -P ./my-vault -n work -i config -f config.json
      seal save -P ./my-vault -n personal -i gmail --interactive
    """
    if interactive:
        payload = {}
        console.print("[dim]Enter key-value pairs (empty key to finish):[/]")
        while True:
            key = click.prompt("  Key", default="")
            if not key:
                break
            value = click.prompt(f"  Value for {key}")
            payload[key] = value
        if not payload:
            console.print("[yellow]No data entered.[/]")
            return
    elif kv_pairs:
        payload = {}
        for pair in kv_pairs:
            if "=" not in pair:
                console.print(f"[red]Error:[/] Invalid key=value format: {pair}")
                return
            k, v = pair.split("=", 1)
            payload[k] = v
    elif data:
        if data.startswith("@"):
            fpath = Path(data[1:])
            if not fpath.exists():
                console.print(f"[red]Error:[/] File not found: {fpath}")
                return
            payload = json.loads(fpath.read_text())
        else:
            payload = json.loads(data)
    elif infile:
        payload = json.load(infile)
    else:
        console.print("[red]Error:[/] Provide --kv, --data, --file, or --interactive.")
        return

    vault = _get_vault(ctx, path, passphrase)
    vault.save(ns, item_id, payload)
    console.print(f"[green]Saved[/] {ns}/{item_id}")


# ─── load ────────────────────────────────────────────────────────────

@cli.command()
@click.option("--path", "-P", envvar="SEAL_VAULT", help="Vault directory path.", type=click.Path())
@click.option("--passphrase", "-p", envvar="SEAL_PASSPHRASE", help="Master passphrase.", hide_input=True)
@click.option("--ns", "-n", required=True, type=click.Choice(["personal", "work", "archive"]), help="Namespace.")
@click.option("--id", "-i", "item_id", required=True, help="Item identifier.")
@click.option("--format", "-F", "fmt", type=click.Choice(["text", "json", "markdown"]), default="json", help="Output format.")
@click.option("--clip", "-c", is_flag=True, help="Copy first value to clipboard (auto-clears after 30s).")
@click.pass_context
@_handle_errors
def load(ctx, path, passphrase, ns, item_id, fmt, clip):
    """Load data from the vault.

    \b
    Examples:
      seal load -P ./my-vault -n personal -i gmail
      seal load -P ./my-vault -n work -i config -F json
      seal load -P ./my-vault -n personal -i gmail --clip
    """
    vault = _get_vault(ctx, path, passphrase)
    result = vault.load(ns, item_id)

    if fmt == "json":
        console.print_json(json.dumps(result))
    elif fmt == "markdown":
        table = Table(title=f"{ns}/{item_id}", show_header=True, border_style="dim")
        table.add_column("Field", style="bold")
        table.add_column("Value")
        for k, v in result.items():
            table.add_row(k, str(v))
        console.print(table)
    else:
        for k, v in result.items():
            console.print(f"  [bold]{k}:[/] {v}")

    if clip:
        try:
            import pyperclip
            first_val = str(next(iter(result.values())))
            pyperclip.copy(first_val)
            console.print(f"\n[dim]Copied to clipboard. Clears in 30 seconds.[/]")
            import threading
            threading.Timer(30.0, lambda: pyperclip.copy("")).start()
        except ImportError:
            console.print("[yellow]pyperclip not installed. Install with: pip install pyperclip[/]")
        except Exception as e:
            console.print(f"[red]Clipboard error:[/] {e}")
    else:
        console.print(f"\n[dim]Tip: use --clip to copy to clipboard instead of displaying.[/]")


# ─── list ────────────────────────────────────────────────────────────

@cli.command("list")
@click.option("--path", "-P", envvar="SEAL_VAULT", help="Vault directory path.", type=click.Path())
@click.option("--passphrase", "-p", envvar="SEAL_PASSPHRASE", help="Master passphrase.", hide_input=True)
@click.option("--ns", "-n", type=click.Choice(["personal", "work", "archive"]), help="Namespace (omit to list all).")
@click.option("--format", "-F", "fmt", type=click.Choice(["text", "json"]), default="text")
@click.option("--long", "-l", is_flag=True, help="Show details (creation date).")
@click.pass_context
@_handle_errors
def list_items(ctx, path, passphrase, ns, fmt, long):
    """List items in the vault.

    \b
    Examples:
      seal list -P ./my-vault -n personal
      seal list -P ./my-vault --long
      seal list -P ./my-vault --format json
    """
    vault = _get_vault(ctx, path, passphrase)
    namespaces = ["personal", "work", "archive"] if not ns else [ns]

    if fmt == "json":
        all_items = {}
        for n in namespaces:
            all_items[n] = vault.list_items(n)
        console.print_json(json.dumps(all_items))
    else:
        for n in namespaces:
            items = vault.list_items(n)
            console.print(f"\n[bold cyan]{n}/[/]")
            if not items:
                console.print(f"  [dim](empty)[/]")
            elif long:
                manifest = vault._manifest
                for item in items:
                    entry = manifest.get("items", {}).get(item, {})
                    created = entry.get("created")
                    if created:
                        ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(created))
                        console.print(f"  {item}  [dim]{ts}[/]")
                    else:
                        console.print(f"  {item}")
            else:
                for item in items:
                    console.print(f"  {item}")


# ─── delete ──────────────────────────────────────────────────────────

@cli.command()
@click.option("--path", "-P", envvar="SEAL_VAULT", help="Vault directory path.", type=click.Path())
@click.option("--passphrase", "-p", envvar="SEAL_PASSPHRASE", help="Master passphrase.", hide_input=True)
@click.option("--ns", "-n", required=True, type=click.Choice(["personal", "work", "archive"]))
@click.option("--id", "-i", "item_id", required=True)
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation.")
@click.pass_context
@_handle_errors
def delete(ctx, path, passphrase, ns, item_id, yes):
    """Delete an item from the vault.

    \b
    Examples:
      seal delete -P ./my-vault -n personal -i doc1
      seal delete -P ./my-vault -n work -i old-config -y
    """
    if not yes:
        click.confirm(f"Delete {ns}/{item_id}?", abort=True)
    vault = _get_vault(ctx, path, passphrase)
    vault.delete(ns, item_id)
    console.print(f"[red]Deleted[/] {ns}/{item_id}")


# ─── verify ──────────────────────────────────────────────────────────

@cli.command()
@click.option("--path", "-P", envvar="SEAL_VAULT", help="Vault directory path.", type=click.Path())
@click.option("--format", "-F", "fmt", type=click.Choice(["text", "json"]), default="text")
@click.pass_context
@_handle_errors
def verify(ctx, path, fmt):
    """Verify vault integrity — audit log chain + canary status.

    \b
    Examples:
      seal verify -P ./my-vault
      seal verify -P ./my-vault --format json
    """
    from aegis.audit import AuditLog
    from aegis.canary import CanaryManager

    vault_path = _resolve_path(ctx, path)
    audit = AuditLog(vault_path)
    chain_ok = audit.verify()
    entry_count = audit.entry_count

    canary_error = None
    try:
        canary = CanaryManager(vault_path)
        triggered = canary.check_all()
    except Exception as e:
        triggered = []
        canary_error = str(e)

    result = {
        "audit_chain": "valid" if chain_ok else "broken",
        "audit_entries": entry_count,
        "canary_status": "clean" if not triggered else "triggered",
        "canary_triggered": len(triggered),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    if canary_error:
        result["canary_error"] = canary_error

    if fmt == "json":
        console.print_json(json.dumps(result))
    else:
        chain_str = "[green]VALID[/]" if chain_ok else "[red]BROKEN[/]"
        if canary_error:
            canary_str = f"[red]CHECK FAILED[/] ({canary_error})"
        elif triggered:
            canary_str = f"[red]{len(triggered)} TRIGGERED[/]"
        else:
            canary_str = "[green]CLEAN[/]"

        hint = ""
        if not chain_ok:
            hint += "\n  [dim]Audit chain is broken — data may have been tampered.[/]"
        if triggered:
            hint += "\n  [dim]Canary files were modified — possible ransomware detected.[/]"
            hint += "\n  [dim]Run 'seal canary check' for details.[/]"

        console.print(Panel(
            f"  Audit Chain:   {chain_str}  ({entry_count} entries)\n"
            f"  Canary Status: {canary_str}\n"
            f"  [dim]Checked: {result['timestamp']}[/]{hint}",
            title="[bold]seal verify[/]",
            border_style="green" if chain_ok and not triggered else "red",
        ))


# ─── canary group ────────────────────────────────────────────────────

@cli.group()
def canary():
    """Ransomware detection via decoy files.

    Seal places fake files (passwords.xlsx, financials.pdf, etc.) in your
    vault and home directories. If ransomware encrypts your real files, it
    encrypts these decoys first — changing their contents. Seal detects this
    change and alerts you before your real data is affected.
    """
    pass


@canary.command()
@click.option("--path", "-P", envvar="SEAL_VAULT", help="Vault directory path.", type=click.Path())
@click.option("--names", help="Comma-separated decoy filenames.")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation.")
@click.pass_context
@_handle_errors
def deploy(ctx, path, names, yes):
    """Deploy decoy canary files.

    Creates fake files like passwords.xlsx and financials.pdf in your
    vault directory, ~/Documents, and ~/Desktop. These are harmless
    decoys used to detect ransomware.

    \b
    Examples:
      seal canary deploy -P ./my-vault
      seal canary deploy -P ./my-vault --names "passwords.xlsx,financials.pdf"
    """
    from aegis.canary import CanaryManager

    if not yes:
        console.print("[yellow]This will create decoy files in:[/]")
        console.print("  - Your vault directory")
        console.print("  - ~/Documents")
        console.print("  - ~/Desktop")
        console.print("[dim]Files: passwords.xlsx, financials.pdf, backup_keys.pem, etc.[/]")
        console.print("[dim]These are harmless fake files used to detect ransomware.[/]")
        click.confirm("\nDeploy canaries?", abort=True)

    name_list = names.split(",") if names else None
    vault_path = _resolve_path(ctx, path)
    mgr = CanaryManager(vault_path)
    created = mgr.deploy(names=name_list)
    console.print(f"[green]Deployed[/] {len(created)} canary file(s).")


@canary.command("check")
@click.option("--path", "-P", envvar="SEAL_VAULT", help="Vault directory path.", type=click.Path())
@click.pass_context
@_handle_errors
def canary_check(ctx, path):
    """Check canary files for tampering.

    \b
    Examples:
      seal canary check -P ./my-vault
    """
    from aegis.canary import CanaryManager

    vault_path = _resolve_path(ctx, path)
    mgr = CanaryManager(vault_path)
    triggered = mgr.check_all()

    if not triggered:
        console.print("[green]All canaries intact.[/]")
    else:
        table = Table(title="CANARY TRIGGERED — Possible ransomware detected", border_style="red")
        table.add_column("File", style="red")
        table.add_column("Status")
        for canary_file, entropy in triggered:
            table.add_row(canary_file.name, "File was modified (content changed)")
        console.print(table)
        console.print(f"\n[dim]Decoy files were tampered with. If you did not do this yourself, your files may be at risk.[/]")


@canary.command()
@click.option("--path", "-P", envvar="SEAL_VAULT", help="Vault directory path.", type=click.Path())
@click.pass_context
@_handle_errors
def remove(ctx, path):
    """Remove all canary decoy files.

    \b
    Examples:
      seal canary remove -P ./my-vault
    """
    from aegis.canary import CanaryManager

    vault_path = _resolve_path(ctx, path)
    mgr = CanaryManager(vault_path)
    count = mgr.remove()
    console.print(f"[yellow]Removed[/] {count} canary file(s).")


# ─── report group ────────────────────────────────────────────────────

@cli.group()
def report():
    """Generate compliance reports.

    Maps your vault's audit log to compliance framework controls
    (SOC 2, HIPAA, GDPR, ISO 27001) and shows which controls
    your usage satisfies.
    """
    pass


@report.command()
@click.option("--path", "-P", envvar="SEAL_VAULT", help="Vault directory path.", type=click.Path())
@click.option("--framework", "-f", required=True, type=click.Choice(["soc2", "hipaa", "gdpr", "iso27001"]),
              help="Compliance framework.")
@click.option("--format", "-F", "fmt", type=click.Choice(["text", "json", "markdown"]), default="text")
@click.pass_context
@_handle_errors
def generate(ctx, path, framework, fmt):
    """Generate a compliance report.

    \b
    Examples:
      seal report generate -P ./my-vault -f soc2
      seal report generate -P ./my-vault -f hipaa -F markdown
      seal report generate -P ./my-vault -f gdpr -F json
    """
    from aegis.audit import AuditLog
    from aegis.report import ComplianceReport

    vault_path = _resolve_path(ctx, path)
    audit = AuditLog(vault_path)
    rpt = ComplianceReport(audit)

    if fmt == "json":
        console.print_json(rpt.export_json(framework))
    elif fmt == "markdown":
        console.print(rpt.export_markdown(framework))
    else:
        result = rpt.generate(framework)
        table = Table(title=result["framework"], border_style="cyan")
        table.add_column("Control", style="bold")
        table.add_column("Status")
        table.add_column("Evidence", justify="right")
        for ctrl_id, ctrl in result["controls"].items():
            status = ctrl["status"]
            style = "green" if status == "COMPLIANT" else "yellow"
            table.add_row(ctrl_id, f"[{style}]{status}[/]", str(ctrl["evidence_count"]))
        console.print(table)
        summary = result["summary"]
        console.print(f"\n  [dim]{summary['compliant']}/{summary['total_controls']} controls compliant[/]")


# ─── share group ─────────────────────────────────────────────────────

@cli.group()
def share():
    """Multi-user key exchange.

    Share vault access with collaborators using X25519 public-key
    cryptography. Each user gets their own keypair — the owner wraps
    the encryption key with the collaborator's public key.
    """
    pass


@share.command()
@click.option("--path", "-P", envvar="SEAL_VAULT", help="Vault directory path.", type=click.Path())
@click.option("--user", "-u", required=True, help="Recipient public key (hex).")
@click.option("--dek", "-d", required=True, help="Encryption key to share (hex).")
@click.pass_context
@_handle_errors
def add(ctx, path, user, dek):
    """Share vault with another user.

    \b
    Examples:
      seal share add -P ./my-vault -u <pubkey-hex> -d <encryption-key-hex>
    """
    from aegis.sharing import ShareManager

    vault_path = _resolve_path(ctx, path)
    sm = ShareManager(vault_path)
    sm.share_vault("user", user, bytes.fromhex(dek))
    console.print("[green]User added.[/]")


@share.command()
@click.option("--path", "-P", envvar="SEAL_VAULT", help="Vault directory path.", type=click.Path())
@click.option("--user", "-u", required=True, help="User ID to remove.")
@click.pass_context
@_handle_errors
def remove(ctx, path, user):
    """Remove user access.

    \b
    Examples:
      seal share remove -P ./my-vault -u <user-id>
    """
    from aegis.sharing import ShareManager

    vault_path = _resolve_path(ctx, path)
    sm = ShareManager(vault_path)
    sm.unshare_vault(user)
    console.print(f"[yellow]User {user} removed.[/]")


@share.command("list")
@click.option("--path", "-P", envvar="SEAL_VAULT", help="Vault directory path.", type=click.Path())
@click.pass_context
@_handle_errors
def share_list(ctx, path):
    """List users with vault access.

    \b
    Examples:
      seal share list -P ./my-vault
    """
    from aegis.sharing import ShareManager

    vault_path = _resolve_path(ctx, path)
    sm = ShareManager(vault_path)
    users = sm.list_users()
    if not users:
        console.print("[dim]No users shared.[/]")
    else:
        for u in users:
            console.print(f"  {u}")


# ─── keygen ──────────────────────────────────────────────────────────

@cli.command()
@_handle_errors
def keygen():
    """Generate a keypair for vault sharing.

    Creates an X25519 keypair. Share the public key with the vault
    owner to get access. Keep the private key secret.

    \b
    Example:
      seal keygen
    """
    from aegis.sharing import ShareManager

    sm = ShareManager(".")
    user_id, pub_hex = sm.generate_keypair()
    console.print(Panel(
        f"[green]Keypair generated.[/]\n\n"
        f"  [bold]Public key:[/]  {pub_hex}\n"
        f"  [bold]User ID:[/]    {user_id}\n\n"
        f"[dim]Share the public key with the vault owner to get access.[/]\n"
        f"[dim]Keep your private key secret — it cannot be recovered.[/]",
        title="[green]seal keygen[/]",
        border_style="green",
    ))


# ─── generate ────────────────────────────────────────────────────────

@cli.command()
@click.option("--length", "-l", default=20, help="Password length.", type=int)
@click.option("--no-symbols", is_flag=True, help="Exclude special characters.")
@click.option("--count", "-n", default=1, help="Number of passwords to generate.")
@click.option("--clip", "-c", is_flag=True, help="Copy to clipboard (auto-clears after 30s).")
@_handle_errors
def generate(length, no_symbols, count, clip):
    """Generate a secure random password.

    \b
    Examples:
      seal generate
      seal generate -l 32
      seal generate -l 16 --no-symbols -n 5
      seal generate --clip
    """
    import secrets
    import string

    chars = string.ascii_letters + string.digits
    if not no_symbols:
        chars += "!@#$%^&*()-_+=[]{}|;':\",./<>?"

    passwords = []
    for _ in range(count):
        pw = "".join(secrets.choice(chars) for _ in range(length))
        passwords.append(pw)

    if clip:
        try:
            import pyperclip
            pyperclip.copy("\n".join(passwords))
            console.print(f"[green]Copied {count} password(s) to clipboard.[/]")
            console.print(f"[dim]Clears in 30 seconds.[/]")
            import threading
            threading.Timer(30.0, lambda: pyperclip.copy("")).start()
        except ImportError:
            console.print("[yellow]pyperclip not installed. Install with: pip install pyperclip[/]")
    else:
        for pw in passwords:
            console.print(f"  {pw}")


# ─── doctor ──────────────────────────────────────────────────────────

@cli.command()
@click.option("--path", "-P", envvar="SEAL_VAULT", help="Vault directory path.", type=click.Path())
@click.pass_context
@_handle_errors
def doctor(ctx, path):
    """Check vault health and configuration.

    \b
    Example:
      seal doctor -P ./my-vault
    """
    from aegis.audit import AuditLog
    from aegis.canary import CanaryManager

    vault_path = _resolve_path(ctx, path)
    checks = []

    # 1. Vault directory exists
    if vault_path.exists():
        checks.append(("Vault directory exists", True, str(vault_path)))
    else:
        checks.append(("Vault directory exists", False, f"Not found: {vault_path}"))
        for status, ok, msg in checks:
            icon = "[green]PASS[/]" if ok else "[red]FAIL[/]"
            console.print(f"  {icon}  {status}: {msg}")
        return

    # 2. Keys directory
    keys_dir = vault_path / "keys"
    if keys_dir.exists():
        checks.append(("Keys directory exists", True, ""))
    else:
        checks.append(("Keys directory exists", False, "Run 'seal init' first"))

    # 3. Manifest
    manifest_path = keys_dir / "manifest.enc"
    if manifest_path.exists():
        checks.append(("Manifest file exists", True, f"{manifest_path.stat().st_size} bytes"))
    else:
        checks.append(("Manifest file exists", False, "No data saved yet"))

    # 4. Audit log
    audit_path = keys_dir / "audit.log"
    if audit_path.exists():
        audit = AuditLog(vault_path)
        chain_ok = audit.verify()
        checks.append(("Audit log chain", chain_ok,
                        f"{audit.entry_count} entries" if chain_ok else "Chain broken — data may be tampered"))
    else:
        checks.append(("Audit log", False, "No audit log yet"))

    # 5. Canary files
    try:
        canary = CanaryManager(vault_path)
        triggered = canary.check_all()
        checks.append(("Canary files", len(triggered) == 0,
                        f"{len(triggered)} TRIGGERED" if triggered else "All intact"))
    except Exception as e:
        checks.append(("Canary files", False, f"Check failed: {e}"))

    # Display
    all_pass = all(ok for _, ok, _ in checks)
    border = "green" if all_pass else "red"
    title = "[green]All checks passed[/]" if all_pass else "[yellow]Some checks failed[/]"

    table = Table(title="seal doctor", border_style=border)
    table.add_column("Status", justify="center")
    table.add_column("Check", style="bold")
    table.add_column("Details", style="dim")
    for check_name, ok, detail in checks:
        icon = "[green]PASS[/]" if ok else "[red]FAIL[/]"
        table.add_row(icon, check_name, detail)
    console.print(table)
    console.print(f"\n  {title}")


# ─── tui ─────────────────────────────────────────────────────────────

@cli.command()
@click.option("--path", "-P", envvar="SEAL_VAULT", help="Vault directory path.", type=click.Path())
@click.pass_context
@_handle_errors
def tui(ctx, path):
    """Launch the interactive TUI vault browser.

    \b
    Examples:
      seal tui -P ./my-vault
    """
    from aegis.tui.app import SealApp

    vault_path = _resolve_path(ctx, path)
    app = SealApp(vault_path=vault_path)
    app.run()


# ─── version ─────────────────────────────────────────────────────────

@cli.command()
def version():
    """Show Seal version."""
    from aegis import __version__
    console.print(f"seal [bold]{__version__}[/]")


if __name__ == "__main__":
    cli()
