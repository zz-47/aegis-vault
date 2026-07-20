from __future__ import annotations

from pathlib import Path

from textual.app import App
from textual.binding import Binding

from aegis.tui._constants import DEFAULT_NAMESPACES
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
        Binding("ctrl+r", "report", "Report"),
        Binding("ctrl+y", "canary", "Canary"),
        Binding("ctrl+o", "open_vault", "Open Vault"),
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
            from aegis.audit import AuditLog
            from aegis.canary import CanaryManager
            from aegis.crypt_storage import AegisVault

            self.passphrase = result.passphrase
            path = self.vault_path or Path.cwd()
            audit = AuditLog(path)
            canary = CanaryManager(path)
            self.vault = AegisVault(path, self.passphrase, audit_log=audit, canary_manager=canary)
            self.push_screen(VaultScreen())
        except Exception as e:
            self.notify(f"Failed to open vault: {e}", severity="error")

    @property
    def base_path(self) -> Path:
        """Return the resolved base path of the vault."""
        if self.vault is not None:
            return self.vault._base_path
        return self.vault_path or Path.cwd()

    def action_verify(self):
        from aegis.audit import AuditLog
        from aegis.canary import CanaryManager

        if not self.vault:
            return
        try:
            audit = AuditLog(self.base_path)
            chain_ok = audit.verify()
            count = audit.entry_count
        except Exception:
            chain_ok, count = False, 0

        try:
            canary = CanaryManager(self.base_path)
            canary_result = canary.check_all()
        except Exception:
            canary_result = None

        status = "VALID" if chain_ok else "BROKEN"
        if canary_result is None:
            canary_status = "CHECK FAILED"
            severity = "error"
        elif canary_result.is_clean:
            canary_status = "CLEAN"
            severity = "info" if chain_ok else "error"
        else:
            t = len(canary_result.triggered)
            m = len(canary_result.missing)
            parts = []
            if t:
                parts.append(f"{t} triggered")
            if m:
                parts.append(f"{m} missing")
            canary_status = ", ".join(parts)
            severity = "error" if not chain_ok else "warning"

        msg = f"Audit Chain: {status} ({count} entries)\nCanary: {canary_status}"
        self.notify(msg, title="Vault Integrity", severity=severity)

    def action_generate(self):
        from aegis.tui.screens.generator import GeneratorScreen
        self.push_screen(GeneratorScreen())

    def action_new_item(self):
        from aegis.tui.screens.vault import NewItemScreen
        self.push_screen(NewItemScreen())

    def action_report(self):
        from aegis.tui.screens.report import ReportScreen
        self.push_screen(ReportScreen())

    def action_canary(self):
        from aegis.tui.screens.canary import CanaryScreen
        self.push_screen(CanaryScreen())

    def action_open_vault(self):
        from aegis.tui.screens.picker import VaultPickerScreen
        self.push_screen(VaultPickerScreen(), self._on_vault_picked)

    def _on_vault_picked(self, result):
        if result is None:
            return
        try:
            from aegis.audit import AuditLog
            from aegis.canary import CanaryManager
            from aegis.crypt_storage import AegisVault

            audit = AuditLog(result)
            canary = CanaryManager(result)
            self.vault = AegisVault(result, self.passphrase, audit_log=audit, canary_manager=canary)
            self.vault_path = result
            self.notify(f"Opened vault: {result}", severity="success")
        except Exception as e:
            self.notify(f"Failed to open vault: {e}", severity="error")
