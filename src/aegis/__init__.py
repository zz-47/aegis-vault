"""Seal — Zero-cloud encrypted file storage with tamper-evident audit."""

__version__ = "0.1.0"

from aegis.crypt_storage import AegisVault
from aegis.audit import AuditLog
from aegis.canary import CanaryManager
from aegis.report import ComplianceReport
from aegis.sharing import ShareManager

__all__ = [
    "AegisVault",
    "AuditLog",
    "CanaryManager",
    "ComplianceReport",
    "ShareManager",
]
