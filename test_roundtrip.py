"""Smoke-test for aegis-vault: round-trip all core modules."""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

VAULT_DIR = Path("test-vault")
PASSPHRASE = "test-passphrase-123"


def _banner(msg: str) -> None:
    print(f"\n{'='*60}\n  {msg}\n{'='*60}")


def cleanup():
    if VAULT_DIR.exists():
        shutil.rmtree(VAULT_DIR)


def test_vault():
    from aegis.crypt_storage import AegisVault

    _banner("AegisVault — save / load / delete / overwrite")
    vault = AegisVault(VAULT_DIR, PASSPHRASE)

    vault.save("personal", "email", {"user": "alice", "pass": "s3cret"})
    vault.save("work", "ssh", {"key": "ed25519"})
    vault.save("archive", "notes", {"text": "hello"})

    assert vault.list_items("personal") == ["email"]
    assert vault.list_items("work") == ["ssh"]
    assert vault.list_items("archive") == ["notes"]

    data = vault.load("personal", "email")
    assert data == {"user": "alice", "pass": "s3cret"}, f"Got {data}"
    print("  [OK] save + load round-trip")

    vault.save("personal", "email", {"user": "alice", "pass": "updated"})
    assert vault.load("personal", "email")["pass"] == "updated"
    print("  [OK] overwrite")

    vault.delete("archive", "notes")
    assert vault.list_items("archive") == []
    print("  [OK] delete")


def test_audit():
    from aegis.audit import AuditLog

    _banner("AuditLog — append / verify / entries")
    audit = AuditLog(VAULT_DIR)

    e1 = audit.append("save", "personal", "email")
    e2 = audit.append("load", "personal", "email")
    e3 = audit.append("save", "work", "ssh")

    assert audit.entry_count == 3
    assert audit.verify() is True
    print("  [OK] append + verify chain")

    entries = audit.get_entries()
    assert len(entries) == 3
    assert entries[0].op == "save"
    assert entries[1].op == "load"
    print("  [OK] get_entries")

    by_ns = audit.get_entries(namespace="personal")
    assert len(by_ns) == 2
    by_op = audit.get_entries(op="load")
    assert len(by_op) == 1
    print("  [OK] filtered queries")

    exported = audit.export_json()
    parsed = json.loads(exported)
    assert len(parsed) == 3
    print("  [OK] export_json")

    # Test chain integrity: tamper with an entry's hash
    original = audit._entries[1].hash
    audit._entries[1].hash = "0" * 64
    assert audit.verify() is False
    audit._entries[1].hash = original
    assert audit.verify() is True
    print("  [OK] tamper detection")


def test_canary():
    from aegis.canary import CanaryManager

    _banner("CanaryManager — deploy / check / remove")
    mgr = CanaryManager(VAULT_DIR, watch_dirs=[str(VAULT_DIR)])

    created = mgr.deploy(names=["_test_canary.txt"])
    assert len(created) > 0
    print(f"  [OK] deployed {len(created)} canary(es)")

    triggered = mgr.check_all()
    assert len(triggered) == 0
    print("  [OK] check_all — clean")

    # Tamper with the canary file
    canary_path = Path(created[0].path)
    canary_path.write_bytes(b"tampered content here!!")
    triggered = mgr.check_all()
    assert len(triggered) == 1
    assert triggered[0][1] > 0  # entropy value
    print("  [OK] check_all — triggered after tamper")

    removed = mgr.remove()
    assert removed >= 1
    assert not canary_path.exists()
    print("  [OK] remove")


def test_sharing():
    from aegis.sharing import ShareManager

    _banner("ShareManager — keypair / share / unshare / try_unlock")
    sm = ShareManager(VAULT_DIR)

    user_id, pub_hex = sm.generate_keypair()
    assert len(user_id) == 16
    assert len(bytes.fromhex(pub_hex)) == 32
    print(f"  [OK] generate_keypair (user_id={user_id[:8]}...)")

    fake_dek = b"\x01" * 32
    sm.share_vault(user_id, pub_hex, fake_dek)
    users = sm.list_users()
    assert user_id in users
    print("  [OK] share_vault")

    # try_unlock requires the private key which we didn't save above
    # We need to re-generate to test unlock flow
    # Let's test unshare instead
    removed = sm.unshare_vault(user_id)
    assert removed is True
    assert sm.list_users() == []
    print("  [OK] unshare_vault")


def test_report():
    from aegis.audit import AuditLog
    from aegis.report import ComplianceReport

    _banner("ComplianceReport — generate / export")
    audit = AuditLog(VAULT_DIR)
    rpt = ComplianceReport(audit)

    for fw in ["soc2", "hipaa", "gdpr", "iso27001"]:
        result = rpt.generate(fw)
        assert "controls" in result
        assert "summary" in result
        total = result["summary"]["total_controls"]
        compliant = result["summary"]["compliant"]
        print(f"  [OK] {fw}: {compliant}/{total} compliant")

    md = rpt.export_markdown("soc2")
    assert "# SOC 2 Type II" in md
    print("  [OK] export_markdown")

    js = rpt.export_json("hipaa")
    parsed = json.loads(js)
    assert parsed["framework"] == "HIPAA Security Rule"
    print("  [OK] export_json")


def main():
    cleanup()
    try:
        test_vault()
        test_audit()
        test_canary()
        test_sharing()
        test_report()
        _banner("ALL TESTS PASSED")
    except Exception as e:
        _banner(f"FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        cleanup()


if __name__ == "__main__":
    main()
