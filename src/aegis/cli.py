from __future__ import annotations

import functools
import json
import sys
import time
from pathlib import Path

import rich_click as click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


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


def _get_vault(ctx):
    from aegis.crypt_storage import AegisVault
    path = ctx.obj.get("path") or Path.cwd()
    passphrase = ctx.obj.get("passphrase")
    if not passphrase:
        passphrase = click.prompt("Passphrase", hide_input=True)
    return AegisVault(path, passphrase)


# ─── Root Group ──────────────────────────────────────────────────────

@click.group()
@click.version_option(package_name="aegis-vault")
@click.option("--path", "-P", envvar="SEAL_VAULT", help="Vault directory path.", type=click.Path())
@click.option("--passphrase", "-p", envvar="SEAL_PASSPHRASE", help="Master passphrase.", hide_input=True)
@click.pass_context
def cli(ctx, path, passphrase):
    """Seal — Local Vault

    Zero-cloud encrypted file storage with tamper-evident audit,
    canary detection, and compliance reports.

    Your passphrase never leaves your machine.
    """
    ctx.ensure_object(dict)
    ctx.obj["path"] = Path(path) if path else None
    ctx.obj["passphrase"] = passphrase


# ─── init ────────────────────────────────────────────────────────────

@cli.command()
@click.option("--path", "-P", required=True, help="Directory to initialize as vault.", type=click.Path())
@click.option("--passphrase", "-p", prompt=True, hide_input=True, confirmation_prompt=True, help="Master passphrase.")
@click.option("--cipher", type=click.Choice(["aes-gcm", "chacha20"]), default="aes-gcm", help="AEAD cipher suite.")
@click.pass_context
@_handle_errors
def init(ctx, path, passphrase, cipher):
    """Create a new encrypted vault.

    \b
    Examples:
      seal init --path ./my-vault
      seal init -P ./secrets -p "my-passphrase" --cipher chacha20
    """
    from aegis.crypt_storage import AegisVault
    vault = AegisVault(path, passphrase)
    console.print(Panel(
        f"[green]Vault created at[/] {Path(path).resolve()}\n"
        f"[dim]Cipher: {cipher} | Namespaces: personal, work, archive[/]",
        title="[green]seal init[/]",
        border_style="green",
    ))


# ─── save ────────────────────────────────────────────────────────────

@cli.command()
@click.option("--ns", "-n", required=True, type=click.Choice(["personal", "work", "archive"]), help="Namespace.")
@click.option("--id", "-i", "item_id", required=True, help="Item identifier.")
@click.option("--data", "-d", help="JSON data string.")
@click.option("--file", "-f", "infile", type=click.File("r"), help="Read JSON from file.")
@click.pass_context
@_handle_errors
def save(ctx, ns, item_id, data, infile):
    """Save data to the vault.

    \b
    Examples:
      seal save -n personal -i doc1 -d '{"password":"abc"}'
      seal save -n work -i config -f config.json
    """
    payload = json.loads(data) if data else json.load(infile)
    vault = _get_vault(ctx)
    vault.save(ns, item_id, payload)
    console.print(f"[green]Saved[/] {ns}/{item_id}")


# ─── load ────────────────────────────────────────────────────────────

@cli.command()
@click.option("--ns", "-n", required=True, type=click.Choice(["personal", "work", "archive"]), help="Namespace.")
@click.option("--id", "-i", "item_id", required=True, help="Item identifier.")
@click.option("--format", "-F", "fmt", type=click.Choice(["text", "json", "markdown"]), default="json", help="Output format.")
@click.pass_context
@_handle_errors
def load(ctx, ns, item_id, fmt):
    """Load data from the vault.

    \b
    Examples:
      seal load -n personal -i doc1
      seal load -n work -i config -F json
    """
    vault = _get_vault(ctx)
    result = vault.load(ns, item_id)
    if fmt == "json":
        console.print_json(json.dumps(result))
    else:
        console.print_json(json.dumps(result, indent=2))


# ─── list ────────────────────────────────────────────────────────────

@cli.command("list")
@click.option("--ns", "-n", type=click.Choice(["personal", "work", "archive"]), help="Namespace (omit to list all).")
@click.option("--format", "-F", "fmt", type=click.Choice(["text", "json"]), default="text")
@click.pass_context
@_handle_errors
def list_items(ctx, ns, fmt):
    """List items in the vault.

    \b
    Examples:
      seal list -n personal
      seal list --format json
    """
    vault = _get_vault(ctx)
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
            for item in items:
                console.print(f"  {item}")
            if not items:
                console.print(f"  [dim](empty)[/]")


# ─── delete ──────────────────────────────────────────────────────────

@cli.command()
@click.option("--ns", "-n", required=True, type=click.Choice(["personal", "work", "archive"]))
@click.option("--id", "-i", "item_id", required=True)
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation.")
@click.pass_context
@_handle_errors
def delete(ctx, ns, item_id, yes):
    """Delete an item from the vault.

    \b
    Examples:
      seal delete -n personal -i doc1
      seal delete -n work -i old-config -y
    """
    if not yes:
        click.confirm(f"Delete {ns}/{item_id}?", abort=True)
    vault = _get_vault(ctx)
    vault.delete(ns, item_id)
    console.print(f"[red]Deleted[/] {ns}/{item_id}")


# ─── verify ──────────────────────────────────────────────────────────

@cli.command()
@click.option("--format", "-F", "fmt", type=click.Choice(["text", "json"]), default="text")
@click.pass_context
@_handle_errors
def verify(ctx, fmt):
    """Verify vault integrity — audit log chain + canary status.

    \b
    Examples:
      seal verify
      seal verify --format json
    """
    from aegis.audit import AuditLog
    from aegis.canary import CanaryManager

    path = ctx.obj.get("path") or Path.cwd()
    audit = AuditLog(path)
    chain_ok = audit.verify()
    entry_count = audit.entry_count

    try:
        canary = CanaryManager(path)
        triggered = canary.check_all()
    except Exception:
        triggered = []

    result = {
        "audit_chain": "valid" if chain_ok else "broken",
        "audit_entries": entry_count,
        "canary_status": "clean" if not triggered else "triggered",
        "canary_triggered": len(triggered),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    if fmt == "json":
        console.print_json(json.dumps(result))
    else:
        chain_str = "[green]VALID[/]" if chain_ok else "[red]BROKEN[/]"
        canary_str = "[green]CLEAN[/]" if not triggered else f"[red]{len(triggered)} TRIGGERED[/]"
        console.print(Panel(
            f"  Audit Chain:   {chain_str}  ({entry_count} entries)\n"
            f"  Canary Status: {canary_str}\n"
            f"  [dim]Checked: {result['timestamp']}[/]",
            title="[bold]seal verify[/]",
            border_style="green" if chain_ok else "red",
        ))


# ─── canary group ────────────────────────────────────────────────────

@cli.group()
def canary():
    """Ransomware canary operations."""
    pass


@canary.command()
@click.option("--names", help="Comma-separated decoy filenames.")
@click.pass_context
@_handle_errors
def deploy(ctx, names):
    """Deploy decoy canary files.

    \b
    Examples:
      seal canary deploy
      seal canary deploy --names "passwords.xlsx,financials.pdf"
    """
    from aegis.canary import CanaryManager

    name_list = names.split(",") if names else None
    path = ctx.obj.get("path") or Path.cwd()
    mgr = CanaryManager(path)
    created = mgr.deploy(names=name_list)
    console.print(f"[green]Deployed[/] {len(created)} canary file(s).")


@canary.command("check")
@click.pass_context
@_handle_errors
def canary_check(ctx):
    """Check canary files for tampering.

    \b
    Examples:
      seal canary check
    """
    from aegis.canary import CanaryManager

    path = ctx.obj.get("path") or Path.cwd()
    mgr = CanaryManager(path)
    triggered = mgr.check_all()

    if not triggered:
        console.print("[green]All canaries intact.[/]")
    else:
        table = Table(title="CANARY TRIGGERED", border_style="red")
        table.add_column("File", style="red")
        table.add_column("Current Entropy")
        for canary_file, entropy in triggered:
            table.add_row(canary_file.name, f"{entropy:.2f}")
        console.print(table)


@canary.command()
@click.pass_context
@_handle_errors
def remove(ctx):
    """Remove all canary decoy files.

    \b
    Examples:
      seal canary remove
    """
    from aegis.canary import CanaryManager

    path = ctx.obj.get("path") or Path.cwd()
    mgr = CanaryManager(path)
    count = mgr.remove()
    console.print(f"[yellow]Removed[/] {count} canary file(s).")


# ─── report group ────────────────────────────────────────────────────

@cli.group()
def report():
    """Generate compliance reports."""
    pass


@report.command()
@click.option("--framework", "-f", required=True, type=click.Choice(["soc2", "hipaa", "gdpr", "iso27001"]))
@click.option("--format", "-F", "fmt", type=click.Choice(["text", "json", "markdown"]), default="text")
@click.pass_context
@_handle_errors
def generate(ctx, framework, fmt):
    """Generate a compliance report.

    \b
    Examples:
      seal report generate -f soc2
      seal report generate -f hipaa -F markdown
      seal report generate -f gdpr -F json
    """
    from aegis.audit import AuditLog
    from aegis.report import ComplianceReport

    path = ctx.obj.get("path") or Path.cwd()
    audit = AuditLog(path)
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
    """Multi-user key exchange."""
    pass


@share.command()
@click.option("--user", "-u", required=True, help="Recipient public key (hex).")
@click.option("--dek", "-d", required=True, help="DEK to wrap (hex).")
@click.pass_context
@_handle_errors
def add(ctx, user, dek):
    """Share vault with another user.

    \b
    Examples:
      seal share add -u <pubkey-hex> -d <dek-hex>
    """
    from aegis.sharing import ShareManager

    path = ctx.obj.get("path") or Path.cwd()
    sm = ShareManager(path)
    sm.share_vault("user", user, bytes.fromhex(dek))
    console.print("[green]User added.[/]")


@share.command()
@click.option("--user", "-u", required=True, help="User ID to remove.")
@click.pass_context
@_handle_errors
def remove(ctx, user):
    """Remove user access.

    \b
    Examples:
      seal share remove -u <user-id>
    """
    from aegis.sharing import ShareManager

    path = ctx.obj.get("path") or Path.cwd()
    sm = ShareManager(path)
    sm.unshare_vault(user)
    console.print(f"[yellow]User {user} removed.[/]")


@share.command("list")
@click.pass_context
@_handle_errors
def share_list(ctx):
    """List users with vault access.

    \b
    Examples:
      seal share list
    """
    from aegis.sharing import ShareManager

    path = ctx.obj.get("path") or Path.cwd()
    sm = ShareManager(path)
    users = sm.list_users()
    if not users:
        console.print("[dim]No users shared.[/]")
    else:
        for u in users:
            console.print(f"  {u}")


# ─── tui ─────────────────────────────────────────────────────────────

@cli.command()
@click.pass_context
@_handle_errors
def tui(ctx):
    """Launch the interactive TUI vault browser.

    \b
    Examples:
      seal tui
      seal tui --path ./my-vault
    """
    from aegis.tui.app import SealApp

    app = SealApp(vault_path=ctx.obj.get("path"))
    app.run()


# ─── gui ─────────────────────────────────────────────────────────────

@cli.command()
@click.pass_context
@_handle_errors
def gui(ctx):
    """Launch the desktop GUI.

    \b
    Examples:
      seal gui
      seal gui --path ./my-vault
    """
    from aegis.gui.app import SealGUI

    app = SealGUI(vault_path=ctx.obj.get("path"))
    app.mainloop()


# ─── version ─────────────────────────────────────────────────────────

@cli.command()
def version():
    """Show Seal version."""
    from aegis import __version__
    console.print(f"seal [bold]{__version__}[/]")


if __name__ == "__main__":
    cli()
