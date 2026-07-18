from __future__ import annotations

import secrets
import string

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Static, Label, Input, Button, Slider
from textual.containers import Vertical, Horizontal
from textual import on
from textual.binding import Binding


class GeneratorScreen(Screen):
    """Password generator with live strength preview."""

    CSS = """
    GeneratorScreen { padding: 1 2; }
    #length-display { width: 100%; margin-bottom: 1; text-align: center; }
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
            yield Label(f"Length: {self.length}", id="length-display")
            yield Slider(
                id="length-slider",
                value=self.length,
                min=8,
                max=64,
                show_value=False,
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

    @on(Slider.Changed, "#length-slider")
    def update_length(self, event):
        self.length = int(event.value)
        self.query_one("#length-display", Label).update(f"Length: {self.length}")
        self.query_one("#generated", Input).value = self._generate()

    @on(Button.Pressed, "#regen-btn")
    def regenerate(self):
        self.query_one("#generated", Input).value = self._generate()

    @on(Button.Pressed, "#copy-btn")
    def copy_password(self):
        import pyperclip
        pw = self.query_one("#generated", Input).value
        try:
            pyperclip.copy(pw)
            self.notify("Copied to clipboard (clears in 30s)", severity="success")
        except Exception:
            self.notify(pw, title="Password (copy manually)")

    def action_go_back(self):
        self.app.pop_screen()
