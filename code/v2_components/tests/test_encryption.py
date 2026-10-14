import pytest
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from common import H
from encryption import RSAScheme, MockKyberHybrid


@pytest.fixture(scope="module")
def rsa():
    return RSAScheme()          # RSA keygen is slow, so create it once


# ---------- RSA-2048 ----------
@pytest.mark.parametrize("n", [1, 64, 128])
def test_rsa_roundtrip(rsa, n):
    m = get_random_bytes(n)
    assert rsa.decrypt(rsa.encrypt(m)) == m


def test_rsa_size_and_randomized(rsa):
    c1, c2 = rsa.encrypt(b"x"), rsa.encrypt(b"x")
    assert len(c1) == 256       # 2048-bit key -> 256-byte ciphertext
    assert c1 != c2             # OAEP is randomized


def test_rsa_wrong_key_fails(rsa):
    other = RSAScheme()
    with pytest.raises(ValueError):
        other.decrypt(rsa.encrypt(b"secret"))


# ---------- Kyber-inspired mock ----------
@pytest.mark.parametrize("sizes", [True, False])
def test_mock_roundtrip(sizes):
    s = MockKyberHybrid(model_sizes=sizes)
    m = get_random_bytes(100)
    assert s.decrypt(s.encrypt(m)) == m


def test_mock_sizes():
    s768 = MockKyberHybrid(model_sizes=True)
    raw = MockKyberHybrid(model_sizes=False)
    assert len(s768.pk) == 1184
    assert len(s768.encrypt(b"x" * 64)) == 1088 + 12 + 16 + 64
    assert len(raw.encrypt(b"x" * 64)) == 32 + 12 + 16 + 64


def test_mock_tamper_detected():
    s = MockKyberHybrid()
    c = bytearray(s.encrypt(b"secret"))
    c[-1] ^= 1                  # flip one bit in the AES-GCM payload
    with pytest.raises(ValueError):
        s.decrypt(bytes(c))


def test_mock_wrong_key_fails():
    a, b = MockKyberHybrid(), MockKyberHybrid()
    with pytest.raises(ValueError):
        b.decrypt(a.encrypt(b"secret"))


def test_mock_KNOWN_INSECURE_public_key_decrypts():
    """Documents the paper's limitation: pk + ciphertext are enough to decrypt."""
    s = MockKyberHybrid()
    c = s.encrypt(b"secret-ehr")
    k = H(s.pk[:32] + c[:32])   # attacker uses only public data
    L = s.kem_len
    plain = AES.new(k, AES.MODE_GCM, nonce=c[L:L + 12]).decrypt_and_verify(
        c[L + 28:], c[L + 12:L + 28]
    )
    assert plain == b"secret-ehr"