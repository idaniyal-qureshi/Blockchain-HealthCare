"""Basic unit tests for the encryption layer.

They only use the public interface (scheme.encrypt / scheme.decrypt and the store / fetch helpers) and run against every
scheme returned by make_schemes(), so they stay the same if the algorithm underneath is changed."""
import json

import pytest
from Crypto.Random import get_random_bytes

from encryption import (
    MockKyberHybrid, make_schemes, record_to_bytes, bytes_to_record,
    encrypt_record, decrypt_record, encrypt_and_store, fetch_and_decrypt,
)
from sensors import edge_records

SCHEMES = make_schemes()                         # key generation once (RSA keygen is slow)
OTHER_KEYS = make_schemes()                      # same algorithms, different key pairs
IDS = [s.name for s in SCHEMES]


@pytest.fixture(scope="module")
def records():
    return edge_records(n_patients=3, n_steps=10)          # small sensor stream: 3 patients x 10 time steps


@pytest.fixture(params=range(len(SCHEMES)), ids=IDS)
def pair(request):
    return SCHEMES[request.param], OTHER_KEYS[request.param]


# ---------- encrypt / decrypt ----------
@pytest.mark.parametrize("n", [1, 64, 128])
def test_roundtrip(pair, n):
    scheme, _ = pair
    m = get_random_bytes(n)
    assert scheme.decrypt(scheme.encrypt(m)) == m


def test_ciphertext_hides_plaintext(pair):
    scheme, _ = pair
    m = b"PATIENT heart_rate=72.31 " * 3
    assert m not in scheme.encrypt(m)


def test_encryption_is_randomized(pair):
    scheme, _ = pair
    assert scheme.encrypt(b"same record") != scheme.encrypt(b"same record")


def test_tampered_ciphertext_rejected(pair):
    scheme, _ = pair
    c = bytearray(scheme.encrypt(b"secret-ehr"))
    c[-1] ^= 1
    with pytest.raises(ValueError):
        scheme.decrypt(bytes(c))


def test_wrong_key_cannot_decrypt(pair):
    scheme, other = pair
    with pytest.raises(ValueError):
        other.decrypt(scheme.encrypt(b"secret-ehr"))


# ---------- sensor records ----------
def test_record_bytes_roundtrip(records):
    for recs in records.values():
        for r in recs:
            assert bytes_to_record(record_to_bytes(r)) == r


def test_sensor_record_roundtrip(pair, records):
    scheme, _ = pair
    rec = records[1][4]
    ct, t_enc = encrypt_record(scheme, rec)
    out, t_dec = decrypt_record(scheme, ct)
    assert out == rec and t_enc > 0 and t_dec > 0


# ---------- store (edge side) + fetch (doctor side) ----------
def test_store_then_fetch_all(pair, records, tmp_path):
    scheme, _ = pair
    store = tmp_path / "store.csv"
    timings = encrypt_and_store([scheme], records, store)
    n = sum(len(v) for v in records.values())
    assert len(timings[scheme.name]["enc"]) == len(timings[scheme.name]["size"]) == n
    decrypted, dec_times = fetch_and_decrypt(scheme, store_path=store)
    assert decrypted == records and len(dec_times) == n


def test_fetch_one_patient(pair, records, tmp_path):
    scheme, _ = pair
    store = tmp_path / "store.csv"
    encrypt_and_store([scheme], records, store)
    decrypted, _ = fetch_and_decrypt(scheme, patient_id=2, store_path=store)
    assert decrypted == {2: records[2]}


def test_store_has_no_plaintext(pair, records, tmp_path):
    scheme, _ = pair
    store = tmp_path / "store.csv"
    encrypt_and_store([scheme], records, store)
    text = store.read_text()
    for r in records[0]:
        assert json.dumps(r["raw"]) not in text


def test_store_wrong_key_cannot_decrypt(pair, records, tmp_path):
    scheme, other = pair
    store = tmp_path / "store.csv"
    encrypt_and_store([scheme], records, store)
    with pytest.raises(ValueError):
        fetch_and_decrypt(other, store_path=store)


# ---------- scheme used by blockchain.py ----------
def test_blockchain_scheme_roundtrip():
    s = MockKyberHybrid()
    rec = json.dumps({"pid": "pseud-1", "hr": [72.1, None, 73.0]}).encode()
    assert s.decrypt(s.encrypt(rec)) == rec
