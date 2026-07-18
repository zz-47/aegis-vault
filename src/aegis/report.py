from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from aegis.audit import AuditLog
from aegis._errors import ConfigError

_FRAMEWORKS = {
    "soc2": {
        "name": "SOC 2 Type II",
        "controls": {
            "CC6.1": {
                "name": "Logical Access Controls",
                "description": "The entity implements logical access security measures.",
                "ops": ["load", "share"],
                "requirement": "Access to encrypted data requires passphrase authentication.",
            },
            "CC6.6": {
                "name": "Encryption at Rest",
                "description": "The entity implements encryption of data at rest.",
                "ops": ["save"],
                "requirement": "All data encrypted with AES-256-GCM per-file DEKs.",
            },
            "CC7.2": {
                "name": "Monitoring",
                "description": "The entity monitors system components for anomalies.",
                "ops": ["verify", "canary_freeze"],
                "requirement": "Tamper-evident audit log with SHA-256 chain verification.",
            },
            "CC8.1": {
                "name": "Change Management",
                "description": "The entity authorizes, designs, develops, tests, and approves changes.",
                "ops": ["save", "delete"],
                "requirement": "All data modifications logged with timestamps and operation type.",
            },
        },
    },
    "hipaa": {
        "name": "HIPAA Security Rule",
        "controls": {
            "164.312(a)(1)": {
                "name": "Access Control",
                "description": "Implement technical policies to allow access only to authorized persons.",
                "ops": ["load", "share"],
                "requirement": "Per-user DEK wrapping via X25519 key exchange.",
            },
            "164.312(a)(2)(iv)": {
                "name": "Encryption and Decryption",
                "description": "Implement mechanism to encrypt and decrypt ePHI.",
                "ops": ["save", "load"],
                "requirement": "AES-256-GCM / ChaCha20-Poly1305 AEAD encryption.",
            },
            "164.312(b)": {
                "name": "Audit Controls",
                "description": "Implement hardware, software, and/or procedural mechanisms to record and examine access.",
                "ops": ["save", "load", "delete", "share"],
                "requirement": "SHA-256 chained tamper-evident audit log.",
            },
            "164.312(d)": {
                "name": "Person or Entity Authentication",
                "description": "Implement procedures to verify identity.",
                "ops": ["unlock", "share"],
                "requirement": "Passphrase + optional biometric authentication.",
            },
        },
    },
    "gdpr": {
        "name": "GDPR (General Data Protection Regulation)",
        "controls": {
            "Art.5(1)(f)": {
                "name": "Integrity and Confidentiality",
                "description": "Personal data processed in a manner ensuring appropriate security.",
                "ops": ["verify", "save"],
                "requirement": "AEAD encryption with tamper-evident audit trail.",
            },
            "Art.25": {
                "name": "Data Protection by Design",
                "description": "Implement appropriate technical measures at design time.",
                "ops": ["save"],
                "requirement": "Zero-cloud architecture, no telemetry, local-only processing.",
            },
            "Art.32": {
                "name": "Security of Processing",
                "description": "Implement appropriate technical and organizational measures.",
                "ops": ["save", "load"],
                "requirement": "Envelope encryption, atomic writes, secure deletion.",
            },
            "Art.33": {
                "name": "Breach Notification",
                "description": "Notify supervisory authority within 72 hours of breach.",
                "ops": ["canary_freeze"],
                "requirement": "Ransomware canary detection with immediate freeze and audit entry.",
            },
        },
    },
    "iso27001": {
        "name": "ISO/IEC 27001:2022",
        "controls": {
            "A.8.24": {
                "name": "Use of Cryptography",
                "description": "Rules for effective use of cryptography.",
                "ops": ["save"],
                "requirement": "AES-256-GCM, PBKDF2 600K iterations, X25519 key exchange.",
            },
            "A.8.15": {
                "name": "Logging",
                "description": "Produce, store, protect and analyse logs.",
                "ops": ["save", "load", "delete"],
                "requirement": "SHA-256 chained append-only audit log.",
            },
            "A.8.12": {
                "name": "Data Leakage Prevention",
                "description": "Apply measures to prevent data leakage.",
                "ops": ["save"],
                "requirement": "Zero-cloud, namespace isolation via AAD binding.",
            },
            "A.8.7": {
                "name": "Protection Against Malware",
                "description": "Implement protection against malware.",
                "ops": ["canary_freeze"],
                "requirement": "Ransomware canary detection with entropy-based monitoring.",
            },
        },
    },
}


class ComplianceReport:

    def __init__(self, audit_log: AuditLog):
        self._audit = audit_log

    def generate(self, framework: str) -> dict:
        if framework not in _FRAMEWORKS:
            available = ", ".join(_FRAMEWORKS.keys())
            raise ConfigError(
                f"Unknown framework '{framework}'. Available: {available}",
                hint="Use 'soc2', 'hipaa', 'gdpr', or 'iso27001'.",
                code="unknown_framework",
            )
        fw = _FRAMEWORKS[framework]
        chain_valid = self._audit.verify()
        entries = self._audit._entries

        controls = {}
        for ctrl_id, ctrl in fw["controls"].items():
            relevant = [e for e in entries if e.op in ctrl["ops"]]
            controls[ctrl_id] = {
                "name": ctrl["name"],
                "description": ctrl["description"],
                "requirement": ctrl["requirement"],
                "status": "COMPLIANT" if relevant or chain_valid else "NO_DATA",
                "evidence_count": len(relevant),
                "sample_operations": [
                    {"op": e.op, "namespace": e.namespace,
                     "item_id": e.item_id, "ts": e.ts}
                    for e in relevant[:5]
                ],
            }

        return {
            "framework": fw["name"],
            "generated_at": time.time(),
            "audit_chain_valid": chain_valid,
            "total_audit_entries": len(entries),
            "controls": controls,
            "summary": {
                "total_controls": len(controls),
                "compliant": sum(1 for c in controls.values()
                                 if c["status"] == "COMPLIANT"),
                "no_data": sum(1 for c in controls.values()
                               if c["status"] == "NO_DATA"),
            },                   
        }

    def export_markdown(self,framework: str) -> str:
        report = self.generate(framework)
        gen_time = time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime(report["generated_at"]),
        )
        chain_status = "VALID" if report["audit_chain_valid"] else "INVALID"
        summary = report["summary"]
        lines = [
            f"# {report['framework']} Compliance Report",
            "",
            f"**Generated:** {gen_time}",
            f"**Audit Chain:** {chain_status}",
            f"**Total Audit Entries:** {report['total_audit_entries']}",
            "",
            "## Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total Controls | {summary['total_controls']} |",
            f"| Compliant | {summary['compliant']} |",
            f"| No Data | {summary['no_data']} |",
            "",
            "## Controls",
            "",
        ]
        for ctrl_id, ctrl in report["controls"].items():
            sample_lines = []
            for op in ctrl["sample_operations"]:
                ts_str = time.strftime(
                    "%Y-%m-%d %H:%M:%S",
                    time.localtime(op["ts"]),
                )
                sample_lines.append(
                    f"- `{op['op']}` on `{op['namespace']}:{op['item_id']}`"
                    f" at {ts_str}"
                )
            lines.extend([
                f"### {ctrl_id}: {ctrl['name']}",
                "",
                f"**Status:** {ctrl['status']}",
                f"**Description:** {ctrl['description']}",
                f"**Requirement:** {ctrl['requirement']}",
                f"**Evidence Count:** {ctrl['evidence_count']}",
                "",
            ])
            if sample_lines:
                lines.append("**Sample Evidence**")
                lines.append("")
                lines.extend(sample_lines)
                lines.append("")
        return "\n".join(lines)  
    
    def export_json(self, framework: str) -> str:
        return json.dumps(self.generate(framework), indent=2)

    def list_frameworks(self) -> list[str]:
        return list(_FRAMEWORKS.keys())
