from __future__ import annotations

from dataclasses import dataclass

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Static, Input, Button, Label
from textual.containers import Vertical
from textual import on, work


@dataclass
class LoginSuccess:
    passphrase: str
    vault_path: str | None


class LoginScreen(ModalScreen):
    """Password entry screen with biometric option."""

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
    #bio-btn {
        width: 100%;
        margin-top: 1;
    }
    #setup-btn {
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

            bio_available = self._check_biometric()
            if bio_available:
                yield Button("Unlock with Windows Hello", id="bio-btn", variant="success")

            yield Button("Save passphrase for next time", id="setup-btn", variant="default")

    def _check_biometric(self) -> bool:
        try:
            from aegis.biometric import BiometricUnlock
            bio = BiometricUnlock()
            return bio._has_biometric
        except Exception:
            return False

    @on(Button.Pressed, "#login-btn")
    @on(Input.Submitted, "#passphrase-input")
    def handle_login(self):
        pw = self.query_one("#passphrase-input", Input).value
        if pw:
            self.dismiss(LoginSuccess(passphrase=pw, vault_path=None))

    @on(Button.Pressed, "#bio-btn")
    def handle_biometric(self):
        bio_btn = self.query_one("#bio-btn", Button)
        bio_btn.label = "Authenticating..."
        bio_btn.disabled = True
        self._run_biometric()

    @work(thread=True, group="biometric")
    def _run_biometric(self):
        try:
            from aegis.biometric import BiometricUnlock
            bio = BiometricUnlock()
            pw = bio.unlock()
            self.app.call_from_thread(self._on_biometric_success, pw)
        except Exception as e:
            self.app.call_from_thread(self._on_biometric_fail, str(e))

    def _on_biometric_success(self, pw):
        if pw:
            self.dismiss(LoginSuccess(passphrase=pw, vault_path=None))

    def _on_biometric_fail(self, error):
        bio_btn = self.query_one("#bio-btn", Button)
        bio_btn.label = "Unlock with Windows Hello"
        bio_btn.disabled = False
        self.notify(f"Biometric failed: {error}", severity="error")

    @on(Button.Pressed, "#setup-btn")
    def handle_setup(self):
        pw = self.query_one("#passphrase-input", Input).value
        if not pw:
            self.notify("Enter passphrase first, then click Save", severity="warning")
            return
        try:
            from aegis.biometric import BiometricUnlock
            bio = BiometricUnlock()
            bio.setup(pw)
            self.notify("Passphrase saved. You can now use Windows Hello.", severity="success")
        except Exception as e:
            self.notify(f"Setup failed: {e}", severity="error")
