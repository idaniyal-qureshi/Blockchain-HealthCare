"""
Encryption layer benchmark  (paper: Sec 4.2, 5.4, 6.5-6.7, Table 2, Figs 7-8)

WHAT THIS FILE DOES
  Compares RSA-2048 (the paper's baseline) with the paper's "Kyber-inspired" mock encryption and measures:
    1. encryption time (ms)
    2. decryption time (ms)
    3. size of one encrypted record (bytes)       -> the paper's Sec 6.7 calls this "memory usage"
    4. Python peak memory while encrypting (bytes) -> the paper's Sec 5.4 "object profiling" (tracemalloc)
  It saves the numbers in RESULTS (used by other parts of the notebook) and draws Fig 7 and Fig 8.

WHERE THIS FILE SITS IN THE FLOW
  The end-to-end flow is controlled by blockchain.py (run_pipeline): sensors -> Fig 2 pipeline -> scheme.encrypt(record) on the
  patient side -> transaction -> Raft consensus -> ledger -> access request (authorization proof + policy + consensus) ->
  scheme.decrypt(ciphertext) on the doctor side. blockchain.py only needs a scheme object with encrypt(bytes) and decrypt(bytes)
  (MockKyberHybrid), so encryption and decryption are already separate calls made at different times.

BENCHMARK DATA FLOW (run() below, Sec 3.2)
  1. sensors.py         : each patient's 5 sensors -> Fig 2 pipeline -> one record per time step (corrected value + 3-5 raw readings);
                          plaintext reference saved to sensor_records.csv
  2. EDGE DEVICE        : run_encryption() / encrypt_and_store(): every patient's device encrypts its own records (public key only)
                          and the ciphertext goes to ONE local storage file: ciphertext_store.csv (local now, cloud later).
                          Nothing is decrypted in this step.
  3. DOCTOR / HOSPITAL  : run_decryption() / fetch_and_decrypt(): fetch the stored ciphertext and decrypt it with the private key,
                          time it and check the result equals the sensor data. Results table saved to encryption_benchmark.csv.

  ASSUMPTION: one key pair per scheme, owned by the hospital. Edge devices only use the PUBLIC key (encrypt);
  the private key stays with the hospital (decrypt).

THE FOUR SCHEMES WE TEST
  - RSA-2048                         : baseline (paper)
  - Kyber-inspired mock (768 sizes)  : the paper's proposed scheme, padded to real Kyber-768 sizes (Sec 4.2 "ciphertext sizes")
  - Kyber-inspired mock (1024 sizes) : our extra test (NOT in the paper), Kyber-1024 sizes
  - Kyber-inspired mock (raw)        : the paper's Table 2 mock exactly as written (32-byte token, no padding)

IMPORTANT (same as the paper, Sec 4.2 and Sec 6.13)
  The mock is a SIMULATION of Kyber's *cost*. It does no lattice maths, and it gives NO real security:
  its "secret" key is the same bytes as the start of the public key, so anyone can rebuild the AES key.
"""

import os
import csv
import time
import json
import base64
import hashlib
import tracemalloc

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

from common import CFG, RESULTS, display  # CFG = settings, RESULTS = shared results dict, display = table printer (works outside Jupyter too)


# =====================================================================
# 1. SETTINGS
# =====================================================================

# Official ML-KEM (Kyber) sizes in bytes, from NIST FIPS 203.
# We only use them to make the mock's outputs the same SIZE as real Kyber.
KYBER_SIZES = {
    768:  {"pk": 1184, "ct": 1088},    # Kyber-768  (the paper's choice)
    1024: {"pk": 1568, "ct": 1568},    # Kyber-1024 (our extra test)
}

TOKEN_SIZE = 32     # random token inside the "encapsulation"
NONCE_SIZE = 12     # AES-GCM nonce
TAG_SIZE   = 16     # AES-GCM authentication tag

STORE_FILE = "ciphertext_store.csv"   # local storage: ONE file holding every patient's ciphertext (columns: scheme, pid, step, ciphertext)
SENSOR_FILE = "sensor_records.csv"    # plaintext reference copy of the sensor records that were encrypted
BENCH_FILE = "encryption_benchmark.csv"   # benchmark results table

# Names used as table rows / dictionary keys (other notebook files may look these up, so keep them the same)
RSA_N   = "RSA-2048"
KY_N    = "Kyber-inspired mock (768 sizes)"
K1024_N = "Kyber-inspired mock (1024 sizes)"
RAW_N   = "Kyber-inspired mock (raw)"


# =====================================================================
# 2. SMALL HELPER FUNCTIONS
# =====================================================================

def sha256(data):
    """Hash -> 32 bytes. 32 bytes = 256 bits = an AES-256 key (Table 2: '256-bit symmetric')."""
    return hashlib.sha256(data).digest()


def filler(seed, length):
    """Make `length` pseudo-random bytes from a seed.
    Stand-in for Kyber's matrix/noise expansion. Its only job is to make the output the right size."""
    if length == 0:
        return b""
    return hashlib.shake_256(seed).digest(length)


def ci95(values):
    """Half-width of the 95% confidence interval of the mean (mean ± this number)."""
    return 1.96 * values.std(ddof=1) / np.sqrt(len(values))


def mean_pm_ci(values, digits=4):
    """Text like '0.1234 ± 0.0012'."""
    return f"{values.mean():.{digits}f} ± {ci95(values):.{digits}f}"


def reduction(new, old):
    """Percent reduction of `new` compared with `old`.
    Positive = new is smaller/faster. Negative = new is BIGGER/slower."""
    return (1 - new / old) * 100


# =====================================================================
# 3. THE ENCRYPTION SCHEMES
# =====================================================================

class RSAScheme:
    """Baseline: RSA-2048 with OAEP padding.
    (The paper only says 'PyCrypto RSA-2048'. OAEP is our assumption because it is the standard safe padding.)"""

    def __init__(self):
        self.name = RSA_N
        key = RSA.generate(2048)                          # make a public/private key pair
        self.encryptor = PKCS1_OAEP.new(key.publickey())  # encrypt with the PUBLIC key
        self.decryptor = PKCS1_OAEP.new(key)              # decrypt with the PRIVATE key

    def encrypt(self, message):          # Eq 3: c = Enc_pk(m)
        return self.encryptor.encrypt(message)            # output is always 256 bytes

    def decrypt(self, record):           # Eq 4: m = Dec_sk(c)
        return self.decryptor.decrypt(record)


class MockKyber:
    """The paper's 'Kyber-inspired hybrid simulation' (Sec 4.2, Sec 5.4, Table 2):
         KeyGen -> Encaps (random public token -> shared 256-bit key) -> AES-GCM.

    Encrypted record layout:
        [ kem_part (token + filler) ][ nonce 12 B ][ tag 16 B ][ encrypted message ]
    """

    def __init__(self, level=768, model_sizes=True):
        if model_sizes:
            self.name = KY_N if level == 768 else K1024_N
            pk_size = KYBER_SIZES[level]["pk"]
            self.kem_size = KYBER_SIZES[level]["ct"]
        else:
            self.name = RAW_N                    # paper's Table 2 mock: just the 32-byte token
            pk_size = TOKEN_SIZE
            self.kem_size = TOKEN_SIZE

        # ---- KeyGen ----
        self.seed = get_random_bytes(32)
        self.public_key = self.seed + filler(self.seed, pk_size - 32)   # padded to Kyber's public-key size
        self.secret_key = self.seed   # NOTE: same bytes as public_key[:32] -> NO secrecy (simulation only)

    # ---- Encapsulation: make a fresh shared key ----
    def encaps(self):
        token = get_random_bytes(TOKEN_SIZE)
        kem_part = token + filler(token, self.kem_size - TOKEN_SIZE)    # padded to Kyber's ciphertext size
        key = sha256(self.public_key[:32] + token)                       # shared key = hash(seed + token)
        return kem_part, key

    # ---- Decapsulation: rebuild the same key from what was received ----
    def decaps(self, kem_part):
        token = kem_part[:TOKEN_SIZE]
        return sha256(self.secret_key + token)                           # = hash(seed + token), same key

    # ---- Eq 3: encrypt ----
    def encrypt(self, message):
        kem_part, key = self.encaps()
        nonce = get_random_bytes(NONCE_SIZE)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(message)
        return kem_part + nonce + tag + ciphertext

    # ---- Eq 4: decrypt ----
    def decrypt(self, record):
        a = self.kem_size          # end of kem_part
        b = a + NONCE_SIZE         # end of nonce
        c = b + TAG_SIZE           # end of tag
        kem_part   = record[:a]
        nonce      = record[a:b]
        tag        = record[b:c]
        ciphertext = record[c:]

        key = self.decaps(kem_part)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)   # raises an error if anything was tampered with


MockKyberHybrid = MockKyber   # old name of the class, still imported by blockchain.py


# =====================================================================
# 4. EDGE DEVICE: ENCRYPT + STORE   (step 2, runs on each patient's device; never decrypts)
# =====================================================================

STORE_COLUMNS = ["scheme", "pid", "step", "ciphertext"]


def record_to_bytes(record):
    """One sensor record (dict) -> compact JSON bytes, e.g.
    {"pid":3,"step":7,"t_s":21,"hr":72.31,"raw":[72.1,71.93,72.45,72.02]}  (about 70-90 bytes, Table 2: 64-128 B)"""
    return json.dumps(record, separators=(",", ":")).encode()


def bytes_to_record(data):
    return json.loads(data)


def encrypt_record(scheme, record):
    """Encrypt ONE sensor record on the patient's edge device (Eq 3: c = Enc_pk(m)). Uses only the public key.
    Returns (ciphertext bytes, encryption time in ms)."""
    message = record_to_bytes(record)
    t0 = time.perf_counter_ns()
    ciphertext = scheme.encrypt(message)
    t1 = time.perf_counter_ns()
    return ciphertext, (t1 - t0) / 1e6                      # nanoseconds -> milliseconds


def encrypt_and_store(schemes, patient_records, store_path=STORE_FILE):
    """Every patient's edge device encrypts its own sensor records; all ciphertext goes to ONE storage file.
    The file is CSV text with one row per record: scheme, pid, step, ciphertext (base64).
    pid / step only say whose record a row is, so the doctor side can fetch it; the readings are only inside the ciphertext.
    Returns {scheme name: {"enc": times in ms, "size": ciphertext bytes, "stored": bytes of base64 text}}."""
    timings = {}
    with open(store_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(STORE_COLUMNS)
        for scheme in schemes:
            scheme.encrypt(b"warm-up")                      # the very first call is always slower, so it is not timed
            enc, size, stored = [], [], 0
            for pid, records in patient_records.items():    # one edge device per patient
                for record in records:
                    ciphertext, t = encrypt_record(scheme, record)
                    text = base64.b64encode(ciphertext).decode("ascii")
                    writer.writerow([scheme.name, pid, record["step"], text])
                    enc.append(t)
                    size.append(len(ciphertext))            # Sec 6.7 "memory usage" = record size
                    stored += len(text)
            timings[scheme.name] = {"enc": np.array(enc), "size": np.array(size), "stored": stored}
    return timings


def encryption_memory(scheme, record, repeats=20):
    """Sec 5.4: Python peak memory while encrypting one record (tracemalloc only sees Python objects, not the C crypto library)."""
    message = record_to_bytes(record)
    peak_mem = []
    for _ in range(repeats):
        tracemalloc.start()
        scheme.encrypt(message)
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peak_mem.append(peak)
    return np.array(peak_mem)


# =====================================================================
# 5. DOCTOR / HOSPITAL SIDE: FETCH + DECRYPT   (last step, after access control / consensus / blockchain)
# =====================================================================

def load_ciphertexts(scheme_name, patient_id=None, store_path=STORE_FILE):
    """Fetch stored ciphertext from the storage file for one scheme (and one patient, or everyone if patient_id is None).
    Returns a list of (pid, step, ciphertext bytes) in the order they were stored."""
    rows = []
    with open(store_path, newline="") as f:
        for row in csv.DictReader(f):
            if row["scheme"] == scheme_name and (patient_id is None or int(row["pid"]) == patient_id):
                rows.append((int(row["pid"]), int(row["step"]), base64.b64decode(row["ciphertext"])))
    return rows


def decrypt_record(scheme, ciphertext):
    """Decrypt ONE stored ciphertext with the private key (Eq 4: m = Dec_sk(c)).
    Returns (record dict, decryption time in ms). Raises ValueError if the ciphertext was tampered with."""
    t0 = time.perf_counter_ns()
    message = scheme.decrypt(ciphertext)
    t1 = time.perf_counter_ns()
    return bytes_to_record(message), (t1 - t0) / 1e6


def fetch_and_decrypt(scheme, patient_id=None, store_path=STORE_FILE):
    """DOCTOR / HOSPITAL side: fetch a patient's ciphertext (or everyone's) from storage and decrypt it.
    In the real flow call this only after the authorization proof has been verified.
    Returns ({pid: [records in time order]}, decryption times in ms)."""
    records, dec_times = {}, []
    for pid, step, ciphertext in load_ciphertexts(scheme.name, patient_id, store_path):
        record, t = decrypt_record(scheme, ciphertext)
        records.setdefault(pid, []).append(record)
        dec_times.append(t)
    return records, dec_times


# =====================================================================
# 6. RESULTS TABLE
# =====================================================================

def make_table(crypto):
    rows = {}
    for name, r in crypto.items():
        rows[name] = {
            "enc_ms":                 mean_pm_ci(r["enc"]),
            "dec_ms":                 mean_pm_ci(r["dec"]),
            "enc_median_ms":          round(float(np.median(r["enc"])), 4),
            "dec_median_ms":          round(float(np.median(r["dec"])), 4),
            "record_bytes (Sec 6.7)": round(float(r["size"].mean()), 1),
            "py_peak_mem_B":          int(r["mem"].mean()),
            "stored_KB (in store file)": round(r["stored"] / 1024, 1),
        }
    return pd.DataFrame(rows).T          # .T = one row per scheme


def save_results(crypto):
    """Put the headline numbers into the shared RESULTS dict (used by other notebook files / the report)."""
    rsa   = crypto[RSA_N]
    ky    = crypto[KY_N]
    k1024 = crypto[K1024_N]
    raw   = crypto[RAW_N]

    RESULTS.update(
        # proposed scheme (768 sizes) vs RSA  -- the paper's main comparison
        enc_red = reduction(ky["enc"].mean(),  rsa["enc"].mean()),
        dec_red = reduction(ky["dec"].mean(),  rsa["dec"].mean()),
        rec_red = reduction(ky["size"].mean(), rsa["size"].mean()),
        mem_red = reduction(ky["mem"].mean(),  rsa["mem"].mean()),

        # record sizes in bytes
        ct_rsa = rsa["size"].mean(),
        ct_ky  = ky["size"].mean(),
        ct_raw = raw["size"].mean(),

        # times in microseconds (the paper's Sec 6.5 quotes decryption in µs)
        rsa_enc_us = rsa["enc"].mean() * 1e3,
        rsa_dec_us = rsa["dec"].mean() * 1e3,
        ky_dec_us  = ky["dec"].mean() * 1e3,

        # our extra: Kyber-1024 sizes vs RSA
        enc_red_1024 = reduction(k1024["enc"].mean(),  rsa["enc"].mean()),
        dec_red_1024 = reduction(k1024["dec"].mean(),  rsa["dec"].mean()),
        rec_red_1024 = reduction(k1024["size"].mean(), rsa["size"].mean()),
        mem_red_1024 = reduction(k1024["mem"].mean(),  rsa["mem"].mean()),
        ct_1024      = k1024["size"].mean(),
    )


# =====================================================================
# 7. FIGURES
# =====================================================================

def plot_fig7(crypto, rounds):
    """Fig 7: encryption time of each sample (first `rounds` samples), log scale."""
    fig, ax = plt.subplots(figsize=(7, 3.5))
    for name in [RSA_N, KY_N, K1024_N]:
        ax.plot(crypto[name]["enc"][:rounds], label=name, lw=1)
    ax.set_yscale("log")                       # log scale because RSA and the mock differ a lot
    ax.set_xlabel("Sample index")
    ax.set_ylabel("Time (ms)")
    ax.set_title(f"Encryption time, {rounds} rounds (cf. Fig 7)")
    ax.legend()
    ax.grid(alpha=0.3)
    plt.savefig("fig07_encryption_time.png", bbox_inches="tight")
    plt.show()


def plot_fig8(crypto):
    """Fig 8: bar charts of mean encryption time, decryption time and record size."""
    names  = [RSA_N, KY_N, K1024_N, RAW_N]
    labels = ["RSA", "Mock\n768", "Mock\n1024", "Mock\nraw"]
    colors = ["tab:red", "tab:green", "tab:blue", "tab:olive"]
    panels = [("enc", "Enc (ms)"), ("dec", "Dec (ms)"), ("size", "Record size (bytes)")]

    fig, axs = plt.subplots(1, 3, figsize=(10, 3.2))
    for ax, (key, title) in zip(axs, panels):
        values = [crypto[n][key].mean() for n in names]
        bars = ax.bar(labels, values, color=colors)
        ax.bar_label(bars, fmt="%.3g", fontsize=7)
        ax.set_title(title)
    fig.suptitle("Cryptographic performance (cf. Fig 8)")
    plt.tight_layout()
    plt.savefig("fig08_crypto_bars.png", bbox_inches="tight")
    plt.show()


# =====================================================================
# 8. RUN: ENCRYPTION AND DECRYPTION ARE SEPARATE STEPS
# =====================================================================

def make_schemes():
    """Key generation (done once, by the hospital). Edge devices receive only the public keys."""
    return [
        RSAScheme(),
        MockKyber(level=768,  model_sizes=True),
        MockKyber(level=1024, model_sizes=True),
        MockKyber(model_sizes=False),
    ]


def run_encryption(patient_records=None, store_path=STORE_FILE):
    """STEP 2 (edge devices): encrypt every patient's sensor records with every scheme and store the ciphertext in ONE file.
    Nothing is decrypted here. patient_records: {pid: [record, ...]}; if None they are generated with sensors.edge_records().
    Returns the state that run_decryption() needs later (the schemes hold the hospital's private keys)."""
    import sensors
    if patient_records is None:
        patient_records = sensors.edge_records()
    sensors.save_records_csv(patient_records, SENSOR_FILE)
    schemes = make_schemes()
    timings = encrypt_and_store(schemes, patient_records, store_path)
    first_record = next(iter(patient_records.values()))[0]
    for scheme in schemes:
        timings[scheme.name]["mem"] = encryption_memory(scheme, first_record)

    n_records = sum(len(r) for r in patient_records.values())
    n_raw = [len(rec["raw"]) for recs in patient_records.values() for rec in recs]
    print(f"Sensor data: {len(patient_records)} patients, {min(n_raw)}-{max(n_raw)} readings per record (mean {np.mean(n_raw):.2f}); "
          f"plaintext reference saved to {SENSOR_FILE}")
    print(f"Edge encryption: {len(patient_records)} patients x {n_records // len(patient_records)} sensor records = {n_records} records per scheme; "
          f"ciphertext stored in {store_path} ({os.path.getsize(store_path) / 1024:.0f} KB). Nothing decrypted yet.")
    display(pd.DataFrame({name: {"enc_ms": mean_pm_ci(t["enc"]), "enc_median_ms": round(float(np.median(t["enc"])), 4),
                                 "record_bytes (Sec 6.7)": round(float(t["size"].mean()), 1), "py_peak_mem_B": int(t["mem"].mean())}
                          for name, t in timings.items()}).T)
    return {"schemes": schemes, "records": patient_records, "store": store_path, "enc": timings}


def run_decryption(state):
    """LAST STEP (doctor / hospital side): fetch the stored ciphertext, decrypt it and check it equals the sensor data,
    then report the full benchmark (Sec 6.5-6.7, Figs 7-8).
    Fills RESULTS and returns rsa_r / ky_r (used by access_control Fig 9 and the energy model)."""
    crypto = {}
    for scheme in state["schemes"]:
        scheme.decrypt(scheme.encrypt(b"warm-up"))          # first call is always slower, so it is not timed
        decrypted, dec_times = fetch_and_decrypt(scheme, store_path=state["store"])
        assert decrypted == state["records"], f"{scheme.name}: decrypted data differs from the sensor data"
        crypto[scheme.name] = dict(state["enc"][scheme.name], dec=np.array(dec_times))

    print(f"Doctor-side decryption: fetched every record from {state['store']}, decrypted it, all records equal the sensor data "
          f"(mean ± 95% CI)")
    table = make_table(crypto)
    display(table)
    table.to_csv(BENCH_FILE, index_label="scheme")
    print(f"Benchmark table saved to {BENCH_FILE}; ciphertext kept in {state['store']}")

    save_results(crypto)
    plot_fig7(crypto, CFG["CRYPTO_ROUNDS"])                 # Fig 7 plots the first CRYPTO_ROUNDS samples
    plot_fig8(crypto)

    return {"CRYPTO": crypto, "rsa_r": crypto[RSA_N], "ky_r": crypto[KY_N]}


def run(patient_records=None):
    """Encryption benchmark called by main.py (and when this file or access_control.py runs on its own): both steps back to back."""
    return run_decryption(run_encryption(patient_records))


if __name__ == "__main__":
    run()
