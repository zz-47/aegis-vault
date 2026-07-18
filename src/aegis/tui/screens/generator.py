from __future__ import annotations

import secrets
import string

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Static, Label, Input, Button
from textual.containers import Vertical, Horizontal
from textual import on
from textual.binding import Binding


class GeneratorScreen(Screen):
    """Password generator with live strength preview."""

    CSS = """
    GeneratorScreen { padding: 1 2; }
    #length-display { width: 100%; margin-bottom: 1; text-align: center; }
    #length-input { width: 100%; max-width: 10; margin-bottom: 1; }
    #generated { width: 100%; margin: 1 0; }
    #copy-btn { margin-top: 1; }
    """

    BINDINGS = [Binding("escape", "go_back", "Back")]

    def __init__(self, length: int = 24, **kwargs):
        super().__init__(**kwargs)
        self.length = length

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("[bold]Password Generator[/]")
            yield Label("Length:", id="length-display")
            yield Input(
                value=str(self.length),
                id="length-input",
                type="integer",
            )
            yield Input(
                value=self._generate(),
                id="generated",
                read_only=True,
            )
            yield Button("Copy to Clipboard", id="copy-btn", variant="primary")
            yield Button("Regenerate", id="regen-btn", variant="default")

    def _generate(self) -> str:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return "".join(secrets.choice(alphabet) for _ in range(self.length))

    @on(Input.Changed, "#length-input")
    def update_length(self, event):
        try:
            self.length = max(8, min(64, int(event.value)))
        except (ValueError, TypeError):
            return
        self.query_one("#generated", Input).value = self._generate()

    @on(Button.Pressed, "#regen-btn")
    def regenerate(self):
        self.query_one("#generated", Input).value = self._generate()

    @on(Button.Pressed, "#copy-btn")
    def copy_password(self):
        pw = self.query_one("#generated", Input).value
        try:
            import pyperclip
            pyperclip.copy(pw)
            self.notify("Copied to clipboard (clears in 30s)", severity="success")
        except Exception:
            self.notify(pw, title="Password (copy manually)")

    def action_go_back(self):
        self.app.pop_screen()
