from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Static, Button, Label, Select, DataTable
from textual.containers import Vertical, Horizontal
from textual import on
from textual.binding import Binding


_FRAMEWORKS = [
    ("soc2", "SOC 2 Type II"),
    ("hipaa", "HIPAA Security Rule"),
    ("gdpr", "GDPR"),
    ("iso27001", "ISO/IEC 27001:2022"),
]


class ReportScreen(Screen):
    """Compliance report viewer."""

    CSS = """
    ReportScreen { padding: 1 2; }
    #framework-select { width: 100%; margin-bottom: 1; }
    #report-table { width: 100%; height: 1fr; }
    #export-md-btn { margin-right: 1; }
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
        yield Label("[bold]Compliance Reports[/]")
        yield Select(
            [(label, key) for key, label in _FRAMEWORKS],
            id="framework-select",
            prompt="Select framework",
        )
        with Horizontal(classes="btn-row"):
            yield Button("Generate", id="gen-btn", variant="primary")
            yield Button("Export Markdown", id="export-md-btn", variant="default")
            yield Button("Export JSON", id="export-json-btn", variant="default")
        yield DataTable(id="report-table")
        yield Static("Esc Back", id="status-bar")

    @on(Button.Pressed, "#gen-btn")
    def generate(self):
        fw = self.query_one("#framework-select", Select).value
        if fw is Select.NULL:
            self.notify("Select a framework first", severity="warning")
            return
        try:
            from aegis.audit import AuditLog
            from aegis.report import ComplianceReport

            audit = AuditLog(self.app.base_path)
            report = ComplianceReport(audit)
            data = report.generate(fw)
        except Exception as e:
            self.notify(f"Report failed: {e}", severity="error")
            return

        table = self.query_one("#report-table", DataTable)
        table.clear()
        table.add_columns("Control", "Name", "Status", "Evidence")

        summary = data["summary"]
        for ctrl_id, ctrl in data["controls"].items():
            status_color = "green" if ctrl["status"] == "COMPLIANT" else "yellow"
            table.add_row(
                ctrl_id,
                ctrl["name"],
                f"[{status_color}]{ctrl['status']}[/]",
                str(ctrl["evidence_count"]),
            )

        chain = "VALID" if data["audit_chain_valid"] else "BROKEN"
        self.query_one("#status-bar", Static).update(
            f"{data['framework']}  |  Chain: {chain}  |  "
            f"{summary['compliant']}/{summary['total_controls']} compliant"
        )

    @on(Button.Pressed, "#export-md-btn")
    def export_markdown(self):
        fw = self.query_one("#framework-select", Select).value
        if fw is Select.NULL:
            self.notify("Select a framework first", severity="warning")
            return
        try:
            from aegis.audit import AuditLog
            from aegis.report import ComplianceReport

            audit = AuditLog(self.app.base_path)
            report = ComplianceReport(audit)
            md = report.export_markdown(fw)
            path = self.app.base_path / f"report_{fw}.md"
            path.write_text(md, encoding="utf-8")
            self.notify(f"Exported to {path}", severity="success")
        except Exception as e:
            self.notify(f"Export failed: {e}", severity="error")

    @on(Button.Pressed, "#export-json-btn")
    def export_json(self):
        fw = self.query_one("#framework-select", Select).value
        if fw is Select.NULL:
            self.notify("Select a framework first", severity="warning")
            return
        try:
            from aegis.audit import AuditLog
            from aegis.report import ComplianceReport

            audit = AuditLog(self.app.base_path)
            report = ComplianceReport(audit)
            js = report.export_json(fw)
            path = self.app.base_path / f"report_{fw}.json"
            path.write_text(js, encoding="utf-8")
            self.notify(f"Exported to {path}", severity="success")
        except Exception as e:
            self.notify(f"Export failed: {e}", severity="error")

    def action_go_back(self):
        self.app.pop_screen()
