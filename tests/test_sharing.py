import pytest
from aegis.sharing import ShareManager, _wrap_dek_for_user, _unwrap_dek_from_stanza
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
import os
import shutil
import tempfile


class TestSharing:

    @pytest.fixture
    def vault_path(self):
        path = tempfile.mkdtemp(prefix="seal_share_test_")
        yield path
        shutil.rmtree(path, ignore_errors=True)

    def test_generate_keypair(self):
        mgr = ShareManager(tempfile.mkdtemp())
        user_id, pub = mgr.generate_keypair()
        assert len(user_id) == 16
        assert len(bytes.fromhex(pub)) == 32

    def test_wrap_unwrap_roundtrip(self):
        dek = os.urandom(32)
        priv = X25519PrivateKey.generate()
        pub = priv.public_key()
        stanza = _wrap_dek_for_user(dek, pub)
        result = _unwrap_dek_from_stanza(stanza, priv)
        assert result == dek

    def test_wrong_key_fails(self):
        dek = os.urandom(32)
        priv1 = X25519PrivateKey.generate()
        priv2 = X25519PrivateKey.generate()
        pub1 = priv1.public_key()
        stanza = _wrap_dek_for_user(dek, pub1)
        result = _unwrap_dek_from_stanza(stanza, priv2)
        assert result is None

    def test_share_unshare(self, vault_path):
        mgr = ShareManager(vault_path)
        user_id, pub = mgr.generate_keypair()
        dek = os.urandom(32)
        mgr.share_vault(user_id, pub, dek)
        assert user_id in mgr.list_users()
        assert mgr.unshare_vault(user_id)
        assert user_id not in mgr.list_users()

    def test_try_unlock(self, vault_path):
        mgr = ShareManager(vault_path)
        user_id, pub = mgr.generate_keypair()
        dek = os.urandom(32)
        mgr.share_vault(user_id, pub, dek)
        priv_hex = os.urandom(32).hex()
        result = mgr.try_unlock(priv_hex)
        assert result is None