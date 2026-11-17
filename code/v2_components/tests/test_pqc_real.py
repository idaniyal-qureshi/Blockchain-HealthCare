"""Conformance tests for the real ML-KEM scheme (pqc_real.py, liboqs).

The universal tests in test_encryption.py already run over every scheme, including these. This file adds what only a real ML-KEM can be
checked against:
  * the FIPS 203 sizes, written out here so the module's own table is not the only source of truth
  * the library really implements the final standard (FIPS 203, IND-CCA) and the legacy Kyber names are refused
  * ML-KEM behaviours: randomised Encaps, implicit rejection, key export / import
  * cross-implementation checks against OpenSSL: a ciphertext made by one library must decapsulate to the same secret in the other,
    in both directions, at all three levels. This stands in for NIST known-answer vectors, which liboqs-python does not expose.

Without liboqs the whole file is skipped. In CI set REQUIRE_PQC=1 so a missing liboqs fails the build instead.
"""
import os
import shutil
import subprocess

import pytest

try:
    import pqc_real as P
except (ImportError, RuntimeError, OSError):
    if os.environ.get("REQUIRE_PQC") == "1":
        raise
    pytest.skip("liboqs / liboqs-python not installed (pip install -r requirements-pqc.txt)", allow_module_level=True)

FIPS_203 = {512: (800, 1632, 768, 32), 768: (1184, 2400, 1088, 32), 1024: (1568, 3168, 1568, 32)}   # pk, sk, ct, shared secret
NIST_LEVEL = {512: 1, 768: 3, 1024: 5}
LEVELS = sorted(FIPS_203)


@pytest.fixture(params=LEVELS, ids=[f"ML-KEM-{n}" for n in LEVELS])
def level(request):
    return request.param


# ---------- the standard ----------
def test_sizes_match_fips203(level):
    pk, sk, ct, ss = FIPS_203[level]
    kp = P.MLKEMKeyPair(level)
    kem_ct, secret = P.encaps(level, kp.public_key)
    assert (len(kp.public_key), len(kp.export_secret_key()), len(kem_ct), len(secret)) == (pk, sk, ct, ss)
    assert kp.decaps(kem_ct) == secret


def test_library_implements_the_final_standard(level):
    info = P.library_info()[f"ML-KEM-{level}"]
    assert info["spec"] == "FIPS203" and info["ind_cca"] is True and info["nist_level"] == NIST_LEVEL[level]


@pytest.mark.parametrize("bad", [0, 256, 999, "Kyber768", "ML-KEM-768"])
def test_unsupported_levels_and_legacy_names_refused(bad):
    with pytest.raises(ValueError):
        P.algorithm_name(bad)


# ---------- ML-KEM behaviour ----------
def test_encaps_is_randomized(level):
    kp = P.MLKEMKeyPair(level)
    (ct1, ss1), (ct2, ss2) = P.encaps(level, kp.public_key), P.encaps(level, kp.public_key)
    assert ct1 != ct2 and ss1 != ss2


def test_implicit_rejection_returns_a_different_secret(level):
    kp = P.MLKEMKeyPair(level)
    kem_ct, secret = P.encaps(level, kp.public_key)
    bad = bytearray(kem_ct)
    bad[len(bad) // 2] ^= 1
    other = kp.decaps(bytes(bad))                       # FIPS 203: no error, a pseudo-random secret
    assert len(other) == 32 and other != secret


def test_wrong_length_inputs_are_rejected(level):
    kp = P.MLKEMKeyPair(level)
    kem_ct, _ = P.encaps(level, kp.public_key)
    with pytest.raises(ValueError):
        P.encaps(level, kp.public_key[:-1])
    with pytest.raises(ValueError):
        kp.decaps(kem_ct[:-1])
    with pytest.raises(ValueError):
        kp.unseal(b"short")


def test_secret_key_export_and_import(level):
    kp = P.MLKEMKeyPair(level)
    record = P.seal(level, kp.public_key, b"patient record")
    restored = P.MLKEMKeyPair(level, secret_key=kp.export_secret_key(), public_key=kp.public_key)
    assert restored.unseal(record) == b"patient record"
    with pytest.raises(ValueError):
        P.MLKEMKeyPair(level, secret_key=b"\x00" * 10, public_key=kp.public_key)


# ---------- the hybrid envelope ----------
def test_envelope_layout_and_size(level):
    msg = b"x" * 80
    record = P.MLKEMHybrid(level).encrypt(msg)
    assert len(record) == FIPS_203[level][2] + P.NONCE_SIZE + P.TAG_SIZE + len(msg)
    assert msg not in record


def test_aad_is_authenticated(level):
    kp = P.MLKEMKeyPair(level)
    record = P.seal(level, kp.public_key, b"m", aad=b"patient-7")
    assert kp.unseal(record, aad=b"patient-7") == b"m"
    for wrong in (b"patient-8", b""):
        with pytest.raises(ValueError):
            kp.unseal(record, aad=wrong)


@pytest.mark.parametrize("enc_level, dec_level", [(512, 768), (768, 1024), (1024, 768)])
def test_record_from_another_level_is_rejected(enc_level, dec_level):
    record = P.MLKEMHybrid(enc_level).encrypt(b"secret-ehr")
    with pytest.raises(ValueError):
        P.MLKEMHybrid(dec_level).decrypt(record)


# ---------- cross-implementation: liboqs <-> OpenSSL ----------
def _openssl(level):
    exe = shutil.which("openssl")
    if exe is None:
        pytest.skip("openssl not found")
    listing = subprocess.run([exe, "list", "-kem-algorithms"], capture_output=True, text=True)
    if listing.returncode != 0 or f"ML-KEM-{level}" not in listing.stdout:
        pytest.skip("this OpenSSL has no ML-KEM (needs 3.5 or newer)")
    return exe


def _run(*args):
    subprocess.run([str(a) for a in args], check=True, capture_output=True, timeout=60)


def _openssl_keypair(exe, level, tmp_path):
    sk, pub = tmp_path / "sk.pem", tmp_path / "pub.der"
    _run(exe, "genpkey", "-algorithm", f"ML-KEM-{level}", "-out", sk)
    _run(exe, "pkey", "-in", sk, "-pubout", "-outform", "DER", "-out", pub)
    return sk, pub.read_bytes()


def test_openssl_decapsulates_what_liboqs_encapsulated(level, tmp_path):
    exe = _openssl(level)
    sk, pub_der = _openssl_keypair(exe, level, tmp_path)
    kem_ct, secret = P.encaps(level, pub_der[-FIPS_203[level][0]:])         # the raw key is the tail of the SubjectPublicKeyInfo
    ct_file, out = tmp_path / "ct.bin", tmp_path / "ss.bin"
    ct_file.write_bytes(kem_ct)
    _run(exe, "pkeyutl", "-decap", "-inkey", sk, "-in", ct_file, "-secret", out)
    assert out.read_bytes() == secret


def test_liboqs_decapsulates_what_openssl_encapsulated(level, tmp_path):
    exe = _openssl(level)
    _, pub_der = _openssl_keypair(exe, level, tmp_path)
    header = pub_der[:-FIPS_203[level][0]]                                  # constant ASN.1 header for this level
    kp = P.MLKEMKeyPair(level)
    pub, ct_file, out = tmp_path / "pub2.der", tmp_path / "ct.bin", tmp_path / "ss.bin"
    pub.write_bytes(header + kp.public_key)
    _run(exe, "pkeyutl", "-encap", "-pubin", "-keyform", "DER", "-inkey", pub, "-out", ct_file, "-secret", out)
    assert kp.decaps(ct_file.read_bytes()) == out.read_bytes()
