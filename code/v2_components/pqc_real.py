"""
Real post-quantum encryption: ML-KEM (NIST FIPS 203) through liboqs, plus AES-256-GCM.

WHAT THIS FILE DOES
  Replaces the paper's "Kyber-inspired" mock (encryption.py: MockKyber) with a real key-encapsulation mechanism and keeps the rest
  identical, so the two schemes can be benchmarked side by side:
      KeyGen  : real ML-KEM key pair
      Encaps  : real lattice encapsulation with the PUBLIC key -> fresh 32-byte shared secret + KEM ciphertext
      key     : HKDF-SHA256(shared secret), bound to the algorithm name and the KEM ciphertext
      AES-GCM : encrypts the record under that key
      record  = [ KEM ciphertext ][ nonce 12 B ][ tag 16 B ][ encrypted message ]      (same layout as MockKyber)
  A scheme object has encrypt(bytes) / decrypt(bytes), like RSAScheme and MockKyber, so every benchmark and test that runs over
  "a scheme" runs over this one unchanged.

KEY OWNERSHIP
  seal() needs only a public key (the patient-side gateway). MLKEMKeyPair holds the secret key and does Decaps (hospital / patient device).
  MLKEMHybrid bundles one key pair behind encrypt/decrypt, the way the other schemes do.

REQUIRES  liboqs (C library) + liboqs-python. See requirements-pqc.txt. Importing this file raises ImportError if they are missing;
  encryption.make_pqc_schemes() turns that into a clear message.

NAMES  Only the final-standard names "ML-KEM-512/768/1024" are used. liboqs also still ships the older "Kyber512/768/1024" drafts,
  which are not byte-compatible with FIPS 203 and are refused here.

LIMITATION  Python bytes cannot be wiped from memory, so secret keys stay in process memory until garbage collected. Fine for a research
  prototype; not for production.
"""
from functools import lru_cache

import oqs
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes

NONCE_SIZE = 12      # AES-GCM nonce (same as encryption.py)
TAG_SIZE = 16        # AES-GCM tag   (same as encryption.py)
KDF_CONTEXT = b"zkblockchain/mlkem-aesgcm/v1"

# FIPS 203, Table 3 (bytes): encapsulation key, decapsulation key, ciphertext, shared secret.
ML_KEM_SIZES = {
    512:  dict(pk=800,  sk=1632, ct=768,  ss=32),
    768:  dict(pk=1184, sk=2400, ct=1088, ss=32),
    1024: dict(pk=1568, sk=3168, ct=1568, ss=32),
}


def algorithm_name(level):
    if level not in ML_KEM_SIZES:
        raise ValueError(f"unsupported ML-KEM level {level}; choose one of {sorted(ML_KEM_SIZES)}")
    return f"ML-KEM-{level}"


def scheme_name(level):
    return f"{algorithm_name(level)} (liboqs)"


def library_info():
    """Versions and algorithm properties to record next to benchmark results."""
    info = {"liboqs": oqs.oqs_version(), "liboqs-python": oqs.oqs_python_version()}
    for level in ML_KEM_SIZES:
        with oqs.KeyEncapsulation(algorithm_name(level)) as kem:
            d = kem.details
            info[algorithm_name(level)] = {"nist_level": d.get("claimed_nist_level"), "ind_cca": d.get("is_ind_cca"), "spec": d.get("version")}
    return info


@lru_cache(maxsize=None)
def _encapsulator(level):
    """Encaps uses no secret key, so one shared liboqs object per level is enough."""
    return oqs.KeyEncapsulation(algorithm_name(level))


def _derive_key(level, shared_secret, kem_ct):
    return HKDF(shared_secret, 32, b"", SHA256, 1, KDF_CONTEXT + b"|" + algorithm_name(level).encode() + b"|" + kem_ct)


def encaps(level, public_key):
    """ML-KEM Encaps with a public key. Returns (KEM ciphertext, 32-byte shared secret)."""
    if len(public_key) != ML_KEM_SIZES[level]["pk"]:
        raise ValueError(f"{algorithm_name(level)} public key must be {ML_KEM_SIZES[level]['pk']} bytes, got {len(public_key)}")
    return _encapsulator(level).encap_secret(public_key)


def seal(level, public_key, message, aad=b""):
    """Encrypt `message` to a public key (Eq 3: c = Enc_pk(m)). Needs no secret. `aad` is authenticated but not stored."""
    kem_ct, shared = encaps(level, public_key)
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(_derive_key(level, shared, kem_ct), AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    data, tag = cipher.encrypt_and_digest(message)
    return kem_ct + nonce + tag + data


class MLKEMKeyPair:
    """An ML-KEM key pair. The secret key stays inside the liboqs object; export_secret_key() copies it out (e.g. for key storage)."""

    def __init__(self, level=768, secret_key=None, public_key=None):
        self.level = level
        self.algorithm = algorithm_name(level)
        sizes = ML_KEM_SIZES[level]
        if secret_key is None:
            self._kem = oqs.KeyEncapsulation(self.algorithm)
            self.public_key = self._kem.generate_keypair()
        else:
            if public_key is None or len(secret_key) != sizes["sk"] or len(public_key) != sizes["pk"]:
                raise ValueError(f"loading a key pair needs a {sizes['sk']}-byte secret key and a {sizes['pk']}-byte public key")
            self._kem = oqs.KeyEncapsulation(self.algorithm, secret_key)
            self.public_key = bytes(public_key)

    def export_secret_key(self):
        return bytes(self._kem.export_secret_key())

    def decaps(self, kem_ct):
        """ML-KEM Decaps. A wrong or tampered ciphertext does not raise: FIPS 203 returns a pseudo-random secret (implicit rejection),
        so the failure shows up later as an AES-GCM tag mismatch."""
        if len(kem_ct) != ML_KEM_SIZES[self.level]["ct"]:
            raise ValueError(f"{self.algorithm} ciphertext must be {ML_KEM_SIZES[self.level]['ct']} bytes, got {len(kem_ct)}")
        return self._kem.decap_secret(kem_ct)

    def unseal(self, record, aad=b""):
        """Decrypt a record made by seal() (Eq 4: m = Dec_sk(c)). Raises ValueError if anything was tampered with or the key is wrong."""
        kem_size = ML_KEM_SIZES[self.level]["ct"]
        if len(record) < kem_size + NONCE_SIZE + TAG_SIZE:
            raise ValueError("ciphertext too short")
        a, b = kem_size, kem_size + NONCE_SIZE
        kem_ct, nonce, tag, data = record[:a], record[a:b], record[b:b + TAG_SIZE], record[b + TAG_SIZE:]
        cipher = AES.new(_derive_key(self.level, self.decaps(kem_ct), kem_ct), AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)
        return cipher.decrypt_and_verify(data, tag)


class MLKEMHybrid:
    """ML-KEM + AES-256-GCM behind the same encrypt/decrypt interface as RSAScheme and MockKyber (one key pair, owned by the hospital)."""

    def __init__(self, level=768):
        self.level = level
        self.name = scheme_name(level)
        self.keypair = MLKEMKeyPair(level)
        self.public_key = self.keypair.public_key
        self.kem_size = ML_KEM_SIZES[level]["ct"]

    def encrypt(self, message):
        return seal(self.level, self.public_key, message)

    def decrypt(self, record):
        return self.keypair.unseal(record)


def make_pqc_schemes(levels=(512, 768, 1024)):
    """One fresh key pair per level. Key generation happens here, not inside any timed call."""
    return [MLKEMHybrid(level) for level in levels]
