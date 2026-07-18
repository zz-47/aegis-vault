from __future__ import annotations

from dataclasses import dataclass

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Static, Input, Button, Label
from textual.containers import Vertical, Horizontal
from textual import on, work


@dataclass
class LoginSuccess:
    passphrase: str
    vault_path: str | None


class LoginScreen(ModalScreen):
    """Password entry screen."""

    CSS = """
    LoginScreen {
        align: center middle;
    }
    #login-box {
        width: 50;
        height: auto;
        padding: 2 4;
        border: thick $primary;
        background: $surface;
    }
    #login-box Label {
        width: 100%;
        text-align: center;
        margin-bottom: 1;
    }
    #passphrase-input {
        width: 100%;
    }
    #login-btn {
        width: 100%;
        margin-top: 1;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="login-box"):
            yield Label("[bold]Seal — Local Vault[/]")
            yield Label("[dim]Enter your master passphrase[/]")
            yield Input(password=True, placeholder="Passphrase", id="passphrase-input")
            yield Button("Unlock", id="login-btn", variant="primary")

    @on(Button.Pressed, "#login-btn")
    @on(Input.Submitted, "#passphrase-input")
    def handle_login(self):
        pw = self.query_one("#passphrase-input", Input).value
        if pw:
            self.dismiss(LoginSuccess(passphrase=pw, vault_path=None))
