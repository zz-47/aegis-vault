from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Static, Input, Button, Label
from textual.containers import Vertical, Horizontal
from textual import on, work
from textual.binding import Binding


class VaultScreen(Screen):
    """Browsable vault listing."""

    CSS = """
    VaultScreen {
        layout: horizontal;
    }
    #sidebar {
        width: 1fr;
        height: 100%;
        border-right: solid $primary;
    }
    #detail {
        width: 2fr;
        height: 100%;
        padding: 1 2;
    }
    #search-bar {
        dock: top;
        height: 3;
        padding: 0 1;
    }
    #status-bar {
        dock: bottom;
        height: 1;
        padding: 0 1;
        background: $accent;
        color: $text;
    }
    """

    BINDINGS = [
        Binding("ctrl+f", "focus_search", "Search"),
        Binding("escape", "go_back", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Input(placeholder="Search entries...", id="search-bar")
        with Vertical(id="sidebar"):
            yield DataTable(id="vault-table")
        with Vertical(id="detail"):
            yield Label("Select an entry", id="detail-label")
            yield Static("", id="detail-content")
        yield Static("Ready", id="status-bar")

    def on_mount(self):
        table = self.query_one("#vault-table", DataTable)
        table.add_columns("Namespace", "Item")
        self._load_items()

    def _load_items(self):
        from aegis.crypt_storage import AegisVault

        app = self.app
        if not app.vault:
            return
        table = self.query_one("#vault-table", DataTable)
        table.clear()
        for ns in ["personal", "work", "archive"]:
            try:
                items = app.vault.list_items(ns)
                for item in items:
                    table.add_row(ns, item)
            except Exception:
                pass
        self.query_one("#status-bar", Static).update(
            f"{table.row_count} entries loaded"
        )

    @on(DataTable.RowSelected)
    def show_entry(self, event):
        if event.row_key is None:
            return
        table = self.query_one("#vault-table", DataTable)
        row = table.get_row(event.row_key)
        ns, item_id = row[0], row[1]
        try:
            data = self.app.vault.load(ns, item_id)
            import json
            self.query_one("#detail-label", Label).update(f"[bold]{ns}/{item_id}[/]")
            self.query_one("#detail-content", Static).update(json.dumps(data, indent=2))
        except Exception as e:
            self.query_one("#detail-content", Static).update(f"[red]Error: {e}[/]")

    @on(Input.Changed, "#search-bar")
    def filter_items(self, event):
        query = event.value.lower()
        table = self.query_one("#vault-table", DataTable)
        for row_key in table.rows:
            row = table.get_row(row_key)
            visible = query in row[0].lower() or query in row[1].lower()
            table.set_row_visible(row_key, visible)

    def action_focus_search(self):
        self.query_one("#search-bar", Input).focus()

    def action_go_back(self):
        self.app.pop_screen()
