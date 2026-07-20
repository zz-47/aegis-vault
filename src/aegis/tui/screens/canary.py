from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Static, Button, Label, Input
from textual.containers import Vertical, Horizontal
from textual import on
from textual.binding import Binding


class CanaryScreen(Screen):
    """Canary deploy / check / remove / status."""

    CSS = """
    CanaryScreen { padding: 1 2; }
    #canary-table { width: 100%; height: 1fr; }
    #status-bar {
        dock: bottom;
        height: 1;
        padding: 0 1;
        background: $accent;
        color: $text;
    }
    .btn-row { height: auto; margin-bottom: 1; }
    .btn-row Button { margin-right: 1; }
    """

    BINDINGS = [Binding("escape", "go_back", "Back")]

    def compose(self) -> ComposeResult:
        yield Label("[bold]Canary Management[/]")
        with Horizontal(classes="btn-row"):
            yield Button("Deploy Canaries", id="deploy-btn", variant="success")
            yield Button("Check All", id="check-btn", variant="primary")
            yield Button("Remove All", id="remove-btn", variant="error")
        yield DataTable(id="canary-table")
        yield Static("Esc Back", id="status-bar")

    def on_mount(self):
        table = self.query_one("#canary-table", DataTable)
        table.add_columns("Name", "Path", "Exists", "Entropy", "Status")
        self._load_status()

    def _load_status(self):
        app = self.app
        if not hasattr(app, "_canary") or app._canary is None:
            try:
                from aegis.canary import CanaryManager
                app._canary = CanaryManager(app.base_path)
            except Exception:
                self.query_one("#status-bar", Static).update("Canary manager unavailable")
                return
        canary = app._canary
        table = self.query_one("#canary-table", DataTable)
        table.clear()
        for entry in canary.status():
            exists = "Yes" if entry["exists"] else "MISSING"
            entropy = f"{entry['entropy']:.2f}"
            table.add_row(entry["name"], entry["path"], exists, entropy, "OK")
        self.query_one("#status-bar", Static).update(
            f"{len(canary.status())} canaries tracked"
        )

    @on(Button.Pressed, "#deploy-btn")
    def deploy(self):
        canary = self.app._canary
        new = canary.deploy()
        self.notify(f"Deployed {len(new)} canary files", severity="success")
        self._load_status()

    @on(Button.Pressed, "#check-btn")
    def check(self):
        canary = self.app._canary
        result = canary.check_all()
        if result.has_alerts:
            parts = []
            if result.triggered:
                names = ", ".join(c.name for c, _, _ in result.triggered)
                parts.append(f"Modified: {names}")
            if result.missing:
                names = ", ".join(c.name for c in result.missing)
                parts.append(f"Missing: {names}")
            self.notify(
                "\n".join(parts),
                title="Canary Alert",
                severity="error",
            )
        else:
            self.notify("All canaries clean", severity="success")
        self._load_status()

    @on(Button.Pressed, "#remove-btn")
    def remove(self):
        canary = self.app._canary
        count = canary.remove()
        self.notify(f"Removed {count} canary files", severity="success")
        self._load_status()

    def action_go_back(self):
        self.app.pop_screen()
