from __future__ import annotations

import math
import secrets
import string
import threading

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Static, Label, Input, Button
from textual.containers import Vertical
from textual import on
from textual.binding import Binding


class GeneratorScreen(Screen):
    """Password generator with strength meter and copy support."""

    CSS = """
    GeneratorScreen { padding: 1 2; }
    #length-display { width: 100%; margin-bottom: 1; text-align: center; }
    #length-input { width: 100%; max-width: 10; margin-bottom: 1; }
    #generated { width: 100%; margin: 1 0; }
    #strength-bar { width: 100%; margin-bottom: 1; text-align: center; }
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
            yield Label(self._strength_label(self.length), id="strength-bar")
            yield Button("Copy to Clipboard", id="copy-btn", variant="primary")
            yield Button("Regenerate", id="regen-btn", variant="default")

    def _generate(self) -> str:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return "".join(secrets.choice(alphabet) for _ in range(self.length))

    def _strength_label(self, length: int) -> str:
        alphabet_size = len(string.ascii_letters + string.digits + "!@#$%^&*")
        entropy = length * math.log2(alphabet_size)
        if entropy < 40:
            color = "red"
            label = "WEAK"
        elif entropy < 60:
            color = "yellow"
            label = "FAIR"
        elif entropy < 80:
            color = "green"
            label = "STRONG"
        else:
            color = "bold green"
            label = "VERY STRONG"
        return f"[{color}]{label}[/]  ({entropy:.0f} bits of entropy)"

    @on(Input.Changed, "#length-input")
    def update_length(self, event):
        try:
            self.length = max(8, min(64, int(event.value)))
        except (ValueError, TypeError):
            return
        self.query_one("#generated", Input).value = self._generate()
        self.query_one("#strength-bar", Label).update(self._strength_label(self.length))

    @on(Button.Pressed, "#regen-btn")
    def regenerate(self):
        self.query_one("#generated", Input).value = self._generate()

    @on(Button.Pressed, "#copy-btn")
    def copy_password(self):
        pw = self.query_one("#generated", Input).value
        try:
            import pyperclip
            pyperclip.copy(pw)
            self.notify("Copied to clipboard. Clears in 30s.", severity="success")
            threading.Timer(30.0, lambda: pyperclip.copy("")).start()
        except ImportError:
            self.notify(pw, title="Password (copy manually)")
        except Exception as e:
            self.notify(f"Copy failed: {e}", severity="error")

    def action_go_back(self):
        self.app.pop_screen()
