from __future__ import annotations

from textual.app import App
from textual.binding import Binding

from aegis.tui.screens.login import LoginScreen
from aegis.tui.screens.vault import VaultScreen


class SealApp(App):
    """Seal TUI — interactive vault browser."""

    TITLE = "Seal — Local Vault"
    SUB_TITLE = "Encrypted password vault"
    CSS_PATH = None
    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit"),
        Binding("ctrl+v", "verify", "Verify"),
        Binding("ctrl+g", "generate", "Generator"),
        Binding("ctrl+n", "new_item", "New Item"),
    ]

    def __init__(self, vault_path=None, **kwargs):
        super().__init__(**kwargs)
        self.vault_path = vault_path
        self.vault = None
        self.passphrase = None

    def on_mount(self):
        self.push_screen(LoginScreen(), self._on_login_result)

    def _on_login_result(self, result):
        if not result:
            return
        try:
            from pathlib import Path
            from aegis.crypt_storage import AegisVault

            self.passphrase = result.passphrase
            path = result.vault_path or self.vault_path or Path.cwd()
            self.vault = AegisVault(path, self.passphrase)
            self.push_screen(VaultScreen())
        except Exception as e:
            self.notify(f"Failed to open vault: {e}", severity="error")

    def action_verify(self):
        from aegis.audit import AuditLog
        from aegis.canary import CanaryManager

        if not self.vault:
            return
        try:
            audit = AuditLog(self.vault._base_path)
            chain_ok = audit.verify()
            count = audit.entry_count
        except Exception:
            chain_ok, count = False, 0

        try:
            canary = CanaryManager(self.vault._base_path)
            triggered = canary.check_all()
        except Exception:
            triggered = []

        status = "VALID" if chain_ok else "BROKEN"
        canary_status = "CLEAN" if not triggered else f"{len(triggered)} TRIGGERED"
        msg = f"Audit Chain: {status} ({count} entries)\nCanary: {canary_status}"
        self.notify(msg, title="Vault Integrity", severity="info" if chain_ok else "error")

    def action_generate(self):
        from aegis.tui.screens.generator import GeneratorScreen
        self.push_screen(GeneratorScreen())

    def action_new_item(self):
        from aegis.tui.screens.vault import NewItemScreen
        self.push_screen(NewItemScreen())
