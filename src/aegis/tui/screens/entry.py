from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Static, Label, Input, Button
from textual.containers import Vertical, Horizontal
from textual import on
from textual.binding import Binding


class EntryScreen(Screen):
    """View/edit a single vault entry."""

    CSS = """
    EntryScreen { padding: 1 2; }
    #entry-id { width: 100%; margin-bottom: 1; }
    #entry-data { width: 100%; height: 1fr; }
    #save-btn { margin-top: 1; }
    """

    BINDINGS = [Binding("escape", "go_back", "Back")]

    def __init__(self, namespace: str, item_id: str, data: dict = None, **kwargs):
        super().__init__(**kwargs)
        self.namespace = namespace
        self.item_id = item_id
        self.data = data or {}

    def compose(self) -> ComposeResult:
        import json
        with Vertical():
            yield Label(f"[bold]{self.namespace}/{self.item_id}[/]", id="entry-id")
            yield Input(
                value=json.dumps(self.data, indent=2),
                id="entry-data",
            )
            yield Button("Save", id="save-btn", variant="primary")

    @on(Button.Pressed, "#save-btn")
    def save_entry(self):
        import json
        raw = self.query_one("#entry-data", Input).value
        try:
            data = json.loads(raw)
            self.app.vault.save(self.namespace, self.item_id, data)
            self.notify("Saved", severity="success")
            self.app.pop_screen()
        except json.JSONDecodeError as e:
            self.notify(f"Invalid JSON: {e}", severity="error")

    def action_go_back(self):
        self.app.pop_screen()
