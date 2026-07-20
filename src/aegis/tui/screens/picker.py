from __future__ import annotations

import json
from pathlib import Path

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Static, Button, Label, Input
from textual.containers import Vertical, Horizontal
from textual import on
from textual.binding import Binding

_DEFAULT_SEARCH_DIRS = [
    Path.home() / "Documents",
    Path.home() / "Desktop",
    Path.home(),
    Path("C:/"),
    Path("D:/"),
]


class VaultPickerScreen(Screen):
    """Discover and select a vault to open."""

    CSS = """
    VaultPickerScreen { padding: 1 2; }
    #search-input { width: 100%; margin-bottom: 1; }
    #vault-table { width: 100%; height: 1fr; }
    .btn-row { height: auto; margin-bottom: 1; }
    .btn-row Button { margin-right: 1; }
    #status-bar {
        dock: bottom;
        height: 1;
        padding: 0 1;
        background: $accent;
        color: $text;
    }
    """

    BINDINGS = [Binding("escape", "go_back", "Back")]

    def compose(self) -> ComposeResult:
        yield Label("[bold]Vault Discovery[/]")
        yield Input(placeholder="Extra search path (optional)", id="search-input")
        with Horizontal(classes="btn-row"):
            yield Button("Scan", id="scan-btn", variant="primary")
            yield Button("Open Selected", id="open-btn", variant="success")
        yield DataTable(id="vault-table")
        yield Static("Esc Back", id="status-bar")

    def on_mount(self):
        table = self.query_one("#vault-table", DataTable)
        table.add_columns("Path", "Entries", "Audit", "Canaries")
        self._selected = None
        self._scan()

    def _scan(self):
        extra = self.query_one("#search-input", Input).value.strip()
        dirs = list(_DEFAULT_SEARCH_DIRS)
        if extra:
            p = Path(extra)
            if p.is_dir() and p not in dirs:
                dirs.insert(0, p)

        table = self.query_one("#vault-table", DataTable)
        table.clear()
        found = 0

        for search_dir in dirs:
            if not search_dir.exists():
                continue
            try:
                for manifest in search_dir.rglob("keys/manifest.enc"):
                    vault_dir = manifest.parent.parent
                    entry_count = self._count_entries(vault_dir)
                    audit_ok = self._check_audit(vault_dir)
                    canary_count = self._count_canaries(vault_dir)
                    table.add_row(
                        str(vault_dir),
                        str(entry_count),
                        "OK" if audit_ok else "BROKEN",
                        str(canary_count),
                    )
                    found += 1
                    if found >= 20:
                        break
            except PermissionError:
                continue
            except Exception:
                continue
            if found >= 20:
                break

        self.query_one("#status-bar", Static).update(f"Found {found} vaults")

    def _count_entries(self, vault_dir: Path) -> int:
        count = 0
        for ns in ("personal", "work", "archive"):
            ns_dir = vault_dir / ns
            if ns_dir.is_dir():
                count += len(list(ns_dir.glob("*.enc")))
        return count

    def _check_audit(self, vault_dir: Path) -> bool:
        try:
            from aegis.audit import AuditLog
            audit = AuditLog(vault_dir)
            return audit.verify()
        except Exception:
            return False

    def _count_canaries(self, vault_dir: Path) -> int:
        manifest = vault_dir / ".canaries" / "canaries.json"
        if manifest.exists():
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
                return len(data)
            except Exception:
                pass
        return 0

    @on(Button.Pressed, "#scan-btn")
    def scan(self):
        self._scan()

    @on(Button.Pressed, "#open-btn")
    def open_selected(self):
        table = self.query_one("#vault-table", DataTable)
        if table.cursor_row is None or table.row_count == 0:
            self.notify("Select a vault first", severity="warning")
            return
        row = table.get_row_at(table.cursor_row)
        vault_path = Path(row[0])
        self.dismiss(vault_path)

    @on(DataTable.RowSelected)
    def select_row(self, event):
        self._selected = event.row_key

    def action_go_back(self):
        self.app.pop_screen()
