from __future__ import annotations

import json
import threading

from textual.app import ComposeResult
from textual.screen import Screen, ModalScreen
from textual.widgets import DataTable, Static, Input, Button, Label, Select, TextArea
from textual.containers import Vertical, Horizontal, ScrollableContainer
from textual import on
from textual.binding import Binding

from aegis.tui._constants import DEFAULT_NAMESPACES


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
    #toolbar {
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
    #copy-btn {
        margin-top: 1;
    }
    """

    BINDINGS = [
        Binding("ctrl+f", "focus_search", "Search"),
        Binding("ctrl+n", "new_item", "New"),
        Binding("ctrl+e", "edit_item", "Edit"),
        Binding("ctrl+d", "delete_item", "Delete"),
        Binding("ctrl+g", "generate", "Generate"),
        Binding("escape", "go_back", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Input(placeholder="Search entries...", id="search-bar")
        with Horizontal(id="toolbar"):
            yield Button("New (Ctrl+N)", id="new-btn", variant="success")
            yield Button("Edit (Ctrl+E)", id="edit-btn", variant="default")
            yield Button("Delete (Ctrl+D)", id="del-btn", variant="error")
        with Vertical(id="sidebar"):
            yield DataTable(id="vault-table")
        with Vertical(id="detail"):
            yield Label("Select an entry", id="detail-label")
            yield Static("", id="detail-content")
            yield Button("Copy Value", id="copy-btn", variant="primary")
        yield Static(
            "Ctrl+N New  Ctrl+E Edit  Ctrl+D Delete  Ctrl+F Search  Ctrl+G Generate  Esc Back",
            id="status-bar",
        )

    def on_mount(self):
        table = self.query_one("#vault-table", DataTable)
        table.add_columns("Namespace", "Item")
        self._all_items = []
        self._selected = None
        self._load_items()

    def on_screen_resume(self) -> None:
        self._load_items()

    def _load_items(self):
        app = self.app
        if not self.app.vault:
            return
        self._all_items = []
        for ns in DEFAULT_NAMESPACES:
            try:
                items = app.vault.list_items(ns)
                for item in items:
                    self._all_items.append((ns, item))
            except FileNotFoundError:
                pass
            except Exception as e:
                self.notify(f"Error loading namespace '{ns}': {e}", severity="warning")
        self._populate_table(self._all_items)
        self.query_one("#status-bar", Static).update(
            f"{len(self._all_items)} entries loaded"
        )

    def _populate_table(self, items):
        table = self.query_one("#vault-table", DataTable)
        table.clear()
        for ns, item_id in items:
            table.add_row(ns, item_id)

    @on(DataTable.RowSelected)
    def show_entry(self, event):
        if event.row_key is None:
            return
        table = self.query_one("#vault-table", DataTable)
        row = table.get_row(event.row_key)
        ns, item_id = row[0], row[1]
        self._selected = (ns, item_id)
        try:
            data = self.app.vault.load(ns, item_id)
            self.query_one("#detail-label", Label).update(f"[bold]{ns}/{item_id}[/]")
            display = json.dumps(data, indent=2)
            self.query_one("#detail-content", Static).update(display)
        except Exception as e:
            self.query_one("#detail-content", Static).update(f"[red]Error: {e}[/]")

    @on(Input.Changed, "#search-bar")
    def filter_items(self, event):
        query = event.value.lower()
        if not query:
            self._populate_table(self._all_items)
        else:
            filtered = [
                (ns, item) for ns, item in self._all_items
                if query in ns.lower() or query in item.lower()
            ]
            self._populate_table(filtered)
        table = self.query_one("#vault-table", DataTable)
        self.query_one("#status-bar", Static).update(
            f"{table.row_count} entries"
        )

    @on(Button.Pressed, "#new-btn")
    def action_new_item(self):
        self.app.push_screen(NewItemScreen())

    @on(Button.Pressed, "#edit-btn")
    def action_edit_item(self):
        if not self._selected:
            self.notify("Select an entry first", severity="warning")
            return
        ns, item_id = self._selected
        try:
            data = self.app.vault.load(ns, item_id)
            self.app.push_screen(EntryScreen(ns, item_id, data))
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    @on(Button.Pressed, "#del-btn")
    def action_delete_item(self):
        if not self._selected:
            self.notify("Select an entry first", severity="warning")
            return
        ns, item_id = self._selected
        self.app.push_screen(DeleteConfirmScreen(ns, item_id))

    def action_focus_search(self):
        self.query_one("#search-bar", Input).focus()

    def action_go_back(self):
        self.app.pop_screen()

    def action_generate(self):
        from aegis.tui.screens.generator import GeneratorScreen
        self.app.push_screen(GeneratorScreen())

    @on(Button.Pressed, "#copy-btn")
    def copy_entry_value(self):
        if not self._selected:
            self.notify("Select an entry first", severity="warning")
            return
        ns, item_id = self._selected
        try:
            data = self.app.vault.load(ns, item_id)
            text = json.dumps(data, indent=2)
            try:
                import pyperclip
                pyperclip.copy(text)
                self.notify(f"Copied {ns}/{item_id} to clipboard. Clears in 30s.", severity="success")
                timer = threading.Timer(30.0, lambda: pyperclip.copy(""))
                timer.daemon = True
                timer.start()
            except ImportError:
                self.notify(text, title=f"{ns}/{item_id}")
        except Exception as e:
            self.notify(f"Copy failed: {e}", severity="error")


class DeleteConfirmScreen(ModalScreen):
    """Confirmation dialog for delete."""

    CSS = """
    DeleteConfirmScreen {
        align: center middle;
    }
    #confirm-box {
        width: 50;
        height: auto;
        padding: 2 4;
        border: thick $error;
        background: $surface;
    }
    #confirm-box Label {
        width: 100%;
        text-align: center;
        margin-bottom: 1;
    }
    #confirm-btn {
        width: 100%;
        margin-top: 1;
    }
    #cancel-btn {
        width: 100%;
        margin-top: 1;
    }
    """

    def __init__(self, namespace: str, item_id: str, **kwargs):
        super().__init__(**kwargs)
        self.namespace = namespace
        self.item_id = item_id

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-box"):
            yield Label("[bold red]Delete Item[/]")
            yield Label(f"Delete [bold]{self.namespace}/{self.item_id}[/]?\n[dim]This cannot be undone.[/]")
            yield Button("Delete", id="confirm-btn", variant="error")
            yield Button("Cancel", id="cancel-btn", variant="default")

    @on(Button.Pressed, "#confirm-btn")
    def confirm_delete(self):
        try:
            self.app.vault.delete(self.namespace, self.item_id)
            self.notify(f"Deleted {self.namespace}/{self.item_id}", severity="success")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")
        self.dismiss(True)

    @on(Button.Pressed, "#cancel-btn")
    def cancel_delete(self):
        self.dismiss(False)


class NewItemScreen(Screen):
    """Create a new vault entry with multiple key-value pairs."""

    CSS = """
    NewItemScreen { padding: 1 2; }
    #ns-select { width: 100%; margin-bottom: 1; }
    #item-id-input { width: 100%; margin-bottom: 1; }
    #kv-container {
        height: 1fr;
        margin-bottom: 1;
    }
    .kv-row {
        height: auto;
        margin-bottom: 0;
    }
    .kv-row Input {
        width: 1fr;
    }
    .kv-key { margin-right: 1; }
    .kv-val { margin-right: 1; }
    .kv-del { width: 5; min-width: 5; }
    #add-field-btn { margin-top: 0; margin-bottom: 1; }
    #save-btn { margin-top: 1; }
    #fields-label { margin-top: 1; }
    """

    BINDINGS = [Binding("escape", "go_back", "Back")]

    def compose(self) -> ComposeResult:
        yield Label("[bold]New Entry[/]")
        yield Select(
            [(ns, ns) for ns in DEFAULT_NAMESPACES],
            id="ns-select",
            prompt="Namespace",
        )
        yield Input(placeholder="Item ID (e.g. gmail, wifi-home)", id="item-id-input")
        yield Label("[dim]Key-value pairs:[/]", id="fields-label")
        with ScrollableContainer(id="kv-container"):
            with Horizontal(classes="kv-row"):
                yield Input(placeholder="Key", classes="kv-key")
                yield Input(placeholder="Value", classes="kv-val")
                yield Button("X", classes="kv-del", variant="error")
        yield Button("+ Add Field", id="add-field-btn", variant="default")
        yield Button("Save", id="save-btn", variant="success")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._field_count = 1

    async def _add_field_row(self):
        container = self.query_one("#kv-container")
        row_count = len(container.query(".kv-row"))
        row = Horizontal(classes="kv-row")
        await container.mount(row, before=row_count)
        await row.mount(Input(placeholder="Key", classes="kv-key"))
        await row.mount(Input(placeholder="Value", classes="kv-val"))
        await row.mount(Button("X", classes="kv-del", variant="error"))

    @on(Button.Pressed, "#add-field-btn")
    async def add_field(self):
        await self._add_field_row()
        self._field_count += 1

    @on(Button.Pressed, ".kv-del")
    def remove_field(self, event):
        row = event.button.parent
        if row and row.has_class("kv-row"):
            rows = list(self.query(".kv-row"))
            if len(rows) > 1:
                row.remove()
                self._field_count -= 1

    @on(Button.Pressed, "#save-btn")
    def save_entry(self):
        ns = self.query_one("#ns-select", Select).value
        if ns is Select.NULL:
            self.notify("Select a namespace", severity="warning")
            return
        item_id = self.query_one("#item-id-input", Input).value.strip()
        if not item_id:
            self.notify("Enter an item ID", severity="warning")
            return

        fields = {}
        for row in self.query(".kv-row"):
            key_input = row.query(".kv-key").first()
            val_input = row.query(".kv-val").first()
            if key_input and val_input:
                k = key_input.value.strip()
                v = val_input.value
                if k:
                    fields[k] = v

        if not fields:
            self.notify("Add at least one field", severity="warning")
            return
        try:
            self.app.vault.save(ns, item_id, fields)
            self.notify(f"Saved {ns}/{item_id}", severity="success")
            self.app.pop_screen()
        except Exception as e:
            self.notify(f"Save failed: {e}", severity="error")

    def action_go_back(self):
        self.app.pop_screen()


class EntryScreen(Screen):
    """View/edit a single vault entry using a TextArea for JSON."""

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
        with Vertical():
            yield Label(f"[bold]{self.namespace}/{self.item_id}[/]", id="entry-id")
            yield TextArea(
                json.dumps(self.data, indent=2),
                id="entry-data",
            )
            yield Button("Save", id="save-btn", variant="primary")

    @on(Button.Pressed, "#save-btn")
    def save_entry(self):
        raw = self.query_one("#entry-data", TextArea).text
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            self.notify(f"Invalid JSON: {e}", severity="error")
            return
        try:
            self.app.vault.save(self.namespace, self.item_id, data)
            self.notify("Saved", severity="success")
            self.app.pop_screen()
        except Exception as e:
            self.notify(f"Save failed: {e}", severity="error")

    def action_go_back(self):
        self.app.pop_screen()
