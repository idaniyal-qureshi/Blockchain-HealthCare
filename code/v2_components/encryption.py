"""2. Encryption layer (Sec. 4.2, 5.4, 6.5-6.7, Figs 7-9)

RSA-2048 baseline vs. the paper's Kyber-768-inspired mock: KeyGen → Encaps (randomised public token → shared key) → AES-GCM (Eqs 3-4, Table 2).
Sec 4.2 says the simulation models "performance costs and ciphertext sizes", so the main mock pads its public key and encapsulation to
real Kyber-768 sizes (1184 B / 1088 B). The paper's literal Table 2 mock (32-byte token) is also measured, as "raw".
Sec 6.7 defines "memory usage" as the size of an encrypted record; Python-level peak memory (Sec 5.4, `tracemalloc`) is reported separately.

Security note (paper limitation, not fixed): in this mock the key is derived from public values, so it has no confidentiality and does not
have the IND-CPA property the paper claims. It is a cost model only. A real KEM (ML-KEM / CRYSTALS-Kyber) would be needed for security.

Library part: RSAScheme, MockKyberHybrid, bench_scheme.  Experiment part: run().
"""
import time, hashlib, tracemalloc
import numpy as np, pandas as pd, matplotlib.pyplot as plt
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from common import CFG, rng, H, ci95, fmt, display, RESULTS

KYBER768 = dict(pk=1184, ct=1088)                                       # FIPS 203 ML-KEM-768 public-key / ciphertext sizes (size model only)

class RSAScheme:
    name = "RSA-2048"
    def __init__(self):                                                 # ASSUMPTION: OAEP padding (paper only says "PyCrypto RSA-2048")
        k = RSA.generate(2048); self._e = PKCS1_OAEP.new(k.publickey()); self._d = PKCS1_OAEP.new(k)
    def encrypt(self, m): return self._e.encrypt(m)                    # Eq 3: c = Enc_pk(m)
    def decrypt(self, c): return self._d.decrypt(c)                    # Eq 4: m = Dec_sk(c)

class MockKyberHybrid:
    """Kyber-inspired hybrid *simulation* (Sec 4.2, Table 2): a randomised public token derives a shared symmetric key that encrypts
    with AES-GCM. No polynomial-ring arithmetic or rejection sampling (as in the paper). model_sizes=True pads pk and the encapsulation
    to Kyber-768 sizes with SHAKE-256 output (a stand-in for Kyber's matrix/noise expansion)."""
    def __init__(self, model_sizes=True):
        self.model_sizes = model_sizes
        self.name = "Kyber-inspired mock (768 sizes)" if model_sizes else "Kyber-inspired mock (raw)"
        seed = get_random_bytes(32)
        self.pk = seed + (hashlib.shake_256(seed).digest(KYBER768["pk"] - 32) if model_sizes else b"")
        self._sk = seed                                                 # mock: decapsulation needs only the seed
        self.kem_len = KYBER768["ct"] if model_sizes else 32
    def encaps(self):
        token = get_random_bytes(32)
        ct_kem = token + (hashlib.shake_256(token).digest(KYBER768["ct"] - 32) if self.model_sizes else b"")
        return ct_kem, H(self.pk[:32] + token)                          # 256-bit shared key (Table 2)
    def decaps(self, ct_kem): return H(self._sk + ct_kem[:32])
    def encrypt(self, m):                                               # Eq 3
        ct_kem, k = self.encaps(); nonce = get_random_bytes(12)
        c, tag = AES.new(k, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(m)
        return ct_kem + nonce + tag + c
    def decrypt(self, c):                                               # Eq 4
        L = self.kem_len; k = self.decaps(c[:L])
        return AES.new(k, AES.MODE_GCM, nonce=c[L:L + 12]).decrypt_and_verify(c[L + 28:], c[L + 12:L + 28])

def bench_scheme(scheme, rounds=CFG["CRYPTO_ROUNDS"], runs=CFG["N_RUNS"]):
    scheme.decrypt(scheme.encrypt(b"warm-up")); enc, dec, size, mem = [], [], [], []
    for _ in range(rounds * runs):
        m = get_random_bytes(int(rng.integers(64, 129)))                # Table 2: 64-128 B simulated EHR payload
        t0 = time.perf_counter_ns(); c = scheme.encrypt(m); t1 = time.perf_counter_ns(); m2 = scheme.decrypt(c); t2 = time.perf_counter_ns()
        assert m2 == m; enc.append((t1 - t0) / 1e6); dec.append((t2 - t1) / 1e6); size.append(len(c))
    for _ in range(20):                                                 # Sec 5.4: Python object profiling (C-library allocations not visible)
        tracemalloc.start(); scheme.encrypt(m); mem.append(tracemalloc.get_traced_memory()[1]); tracemalloc.stop()
    return dict(enc=np.array(enc), dec=np.array(dec), size=np.array(size), mem=np.array(mem))


def run():
    """Crypto benchmark (Sec 6.5-6.7, Figs 7-8). Fills RESULTS and returns rsa_r / ky_r (used by access_control Fig 9 and the energy model)."""
    schemes = [RSAScheme(), MockKyberHybrid(model_sizes=True), MockKyberHybrid(model_sizes=False)]
    CRYPTO = {s.name: bench_scheme(s) for s in schemes}
    crypto_df = pd.DataFrame({n: {"enc_ms": fmt(r["enc"].mean(), ci95(r["enc"]), 4), "dec_ms": fmt(r["dec"].mean(), ci95(r["dec"]), 4),
                                  "enc_median_ms": round(float(np.median(r["enc"])), 4), "dec_median_ms": round(float(np.median(r["dec"])), 4),
                                  "record_bytes (Sec 6.7)": round(r["size"].mean(), 1), "py_peak_mem_B": int(r["mem"].mean())}
                              for n, r in CRYPTO.items()}).T
    print(f"{CFG['CRYPTO_ROUNDS']} rounds x {CFG['N_RUNS']} runs per scheme (mean ± 95% CI)"); display(crypto_df)
    RSA_N, KY_N, RAW_N = "RSA-2048", "Kyber-inspired mock (768 sizes)", "Kyber-inspired mock (raw)"
    rsa_r, ky_r = CRYPTO[RSA_N], CRYPTO[KY_N]
    RESULTS.update(enc_red=(1 - ky_r["enc"].mean() / rsa_r["enc"].mean()) * 100, dec_red=(1 - ky_r["dec"].mean() / rsa_r["dec"].mean()) * 100,
                   ct_ky=ky_r["size"].mean(), ct_raw=CRYPTO[RAW_N]["size"].mean(), ct_rsa=rsa_r["size"].mean(),
                   rec_red=(1 - ky_r["size"].mean() / rsa_r["size"].mean()) * 100, mem_red=(1 - ky_r["mem"].mean() / rsa_r["mem"].mean()) * 100,
                   rsa_enc_us=rsa_r["enc"].mean() * 1e3, rsa_dec_us=rsa_r["dec"].mean() * 1e3, ky_dec_us=ky_r["dec"].mean() * 1e3)

    # ---------------- Figs 7-8 ----------------
    fig, ax = plt.subplots(figsize=(7, 3.5))                                # Fig 7
    for n in (RSA_N, KY_N): ax.plot(CRYPTO[n]["enc"][:CFG["CRYPTO_ROUNDS"]], label=n, lw=1)
    ax.set_yscale("log"); ax.set_xlabel("Sample index"); ax.set_ylabel("Time (ms)"); ax.legend(); ax.grid(alpha=.3)
    ax.set_title("Encryption time, 100 rounds (cf. Fig 7)"); plt.savefig("fig07_encryption_time.png", bbox_inches="tight"); plt.show()
    fig, axs = plt.subplots(1, 3, figsize=(10, 3.2))                        # Fig 8
    for a, (k, lab) in zip(axs, [("enc", "Enc (ms)"), ("dec", "Dec (ms)"), ("size", "Record size (bytes)")]):
        vals = [CRYPTO[n][k].mean() for n in (RSA_N, KY_N, RAW_N)]
        b = a.bar(["RSA", "Mock\n768", "Mock\nraw"], vals, color=["tab:red", "tab:green", "tab:olive"]); a.bar_label(b, fmt="%.3g", fontsize=7); a.set_title(lab)
    fig.suptitle("Cryptographic performance (cf. Fig 8)"); plt.tight_layout(); plt.savefig("fig08_crypto_bars.png", bbox_inches="tight"); plt.show()
    return dict(CRYPTO=CRYPTO, rsa_r=rsa_r, ky_r=ky_r)


if __name__ == "__main__":
    run()
