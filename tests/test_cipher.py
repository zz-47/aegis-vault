import os
import pytest
from aegis.cipher import AeadCipher, CipherConfig, CipherSuite
from aegis._errors import LocalStorageError, DecryptionError


class TestAeadCipher:

    def test_generate_key_length(self):
        cipher = AeadCipher()
        key = cipher.generate_key()
        assert len(key) == 32

    def test_encrypt_decrypt_roundtrip(self):
        cipher = AeadCipher()
        key = cipher.generate_key()
        plaintext = b"hello world"
        aad = b"personal/doc_01"
        ct, nonce, tag = cipher.encrypt(key, plaintext, aad)
        result = cipher.decrypt(key, ct, nonce, tag, aad)
        assert result == plaintext

    def test_combined_roundtrip(self):
        cipher = AeadCipher()
        key = cipher.generate_key()
        plaintext = b"combined test"
        aad = b"work/doc_02"
        blob = cipher.encrypt_combined(key, plaintext, aad)
        result = cipher.decrypt_combined(key, blob, aad)
        assert result == plaintext

    def test_wrong_key_fails(self):
        cipher = AeadCipher()
        key = cipher.generate_key()
        wrong_key = cipher.generate_key()
        ct, nonce, tag = cipher.encrypt(key, b"secret", b"ns:test")
        with pytest.raises(DecryptionError):
            cipher.decrypt(wrong_key, ct, nonce, tag, b"ns:test")

    def test_tampered_ciphertext_fails(self):
        cipher = AeadCipher()
        key = cipher.generate_key()
        ct, nonce, tag = cipher.encrypt(key, b"secret", b"ns:test")
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with pytest.raises(DecryptionError):
            cipher.decrypt(key, bytes(tampered), nonce, tag, b"ns:test")

    def test_wrong_aad_fails(self):
        cipher = AeadCipher()
        key = cipher.generate_key()
        ct, nonce, tag = cipher.encrypt(key, b"secret", b"ns:personal")
        with pytest.raises(DecryptionError):
            cipher.decrypt(key, ct, nonce, tag, b"ns:work")

    def test_wrong_tag_fails(self):
        cipher = AeadCipher()
        key = cipher.generate_key()
        ct, nonce, tag = cipher.encrypt(key, b"secret", b"ns:test")
        bad_tag = bytearray(tag)
        bad_tag[0] ^= 0xFF
        with pytest.raises(DecryptionError):
            cipher.decrypt(key, ct, nonce, bytes(bad_tag), b"ns:test")

    def test_empty_plaintext(self):
        cipher = AeadCipher()
        key = cipher.generate_key()
        blob = cipher.encrypt_combined(key, b"", b"ns:test")
        result = cipher.decrypt_combined(key, blob, b"ns:test")
        assert result == b""

    def test_large_plaintext(self):
        cipher = AeadCipher()
        key = cipher.generate_key()
        plaintext = os.urandom(1024 * 1024)
        blob = cipher.encrypt_combined(key, plaintext, b"ns:test")
        result = cipher.decrypt_combined(key, blob, b"ns:test")
        assert result == plaintext

    def test_chacha20_roundtrip(self):
        config = CipherConfig(suite=CipherSuite.CHACHA20_POLY1305)
        cipher = AeadCipher(config)
        key = cipher.generate_key()
        blob = cipher.encrypt_combined(key, b"chacha test", b"ns:test")
        result = cipher.decrypt_combined(key, blob, b"ns:test")
        assert result == b"chacha test"

    def test_invalid_key_size(self):
        cipher = AeadCipher()
        with pytest.raises(LocalStorageError):
            cipher.encrypt(b"short", b"data")

    def test_multiple_encryptions_unique_nonces(self):
        cipher = AeadCipher()
        key = cipher.generate_key()
        _, n1, _ = cipher.encrypt(key, b"data", b"aad")
        _, n2, _ = cipher.encrypt(key, b"data", b"aad")
        assert n1 != n2
