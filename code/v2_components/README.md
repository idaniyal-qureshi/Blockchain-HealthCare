# v2 components

`hospital_blockchain_paper_impl_v2.ipynb` split into one file per component. The code is the notebook's code wrapped in functions, except
`access_control.py`, which was rewritten to follow the paper exactly (Eqs 5-10 and 17, Algorithms 3-4, Table 2) instead of the notebook's
patched design; its `# GAP`, `# PAPER-CONFLICT` and `# PAPER-FLAW` tags mark where the paper is silent, contradicts itself or is weak.

Hao et al. (PLOS ONE 20(12): e0332887, 2025), *Post-quantum-inspired scalable blockchain architecture for internet hospital systems with
lightweight privacy-preserving access control*. As in the paper, the "Kyber-inspired" encryption is a mock (randomised public token → AES-GCM,
no lattice arithmetic) and the "authorization proof" is a SHA-256 hash commitment, not a zk-SNARK.

| File | Notebook cells | What it holds |
|---|---|---|
| `common.py` | 0-2 | imports, seed, `H`, `ci95`, `fmt`, the `CFG` parameter table, shared `RESULTS` dict |
| `sensors.py` | 3-4 | 1. Fault-tolerant sensor ingestion: Algorithms 1-2, Kalman baseline, Fig 2 pipeline, Figs 10-11 |
| `encryption.py` | 5-6 | 2. Encryption layer: RSA-2048 vs Kyber-inspired mock, Figs 7-8 |
| `access_control.py` | (rewritten) | 3. Access control exactly as in the paper: hash commitment p = H(s), Algorithms 3-4, policies (Eqs 8-10), RBAC baseline, Figs 3 and 9 |
| `consensus.py` | 9-10 | 4. Consensus simulator: Raft, PBFT, HotStuff, Tendermint, Figs 4-6, 12, Table 3 |
| `blockchain.py` | 11-12 | 5. Ledger, end-to-end data flow, threat model, storage, Eq 13 energy, Fig 13 |
| `report.py` | 13-14 | Paper's reported values vs. this run |
| `ASSUMPTIONS.md` | 15 | Assumptions and the paper's self-contradictions |
| `main.py` | – | Runs everything in notebook order |

Each component file has a library part (classes/functions, safe to import) and a `run()` that performs that section's experiments and plots.
The section's explanation from the notebook is the file's docstring.

## How the parts depend on each other

```
common ─┬─ sensors ──────────────┐  PIPE (retransmissions)
        ├─ encryption ───────────┤  rsa_r, ky_r (timings)
        ├─ access_control ───────┤  uses ky_r for Fig 9; RESULTS["proof_gen_ms"]
        ├─ consensus ────────────┤  g() lookup into the consensus results
        └─ blockchain ◄──────────┘  uses all four (end-to-end run + energy)
           report  ◄── RESULTS from everything
```

## Running

```bash
pip install pycryptodome numpy pandas matplotlib scipy
cd code/v2_components
python main.py            # all parts, figures saved to ./output   (--show to open figure windows)
python sensors.py         # one part on its own (also encryption.py, access_control.py, consensus.py)
```

`blockchain.py` and `report.py` need the earlier parts, so running them directly runs `main.py`.
Running a single part on its own draws different random numbers from the shared seed than the full run, so its numbers can differ slightly
from `main.py` / the notebook.

## Real ML-KEM extension (post-quantum encryption)

The baseline above reproduces the paper, including its mock "Kyber". These files replace the mock with real ML-KEM (NIST FIPS 203, liboqs).
They are additive: nothing in the paper baseline imports them, and the baseline needs no C library.

| File | What it holds |
|---|---|
| `pqc_real.py` | ML-KEM-512/768/1024 + AES-256-GCM scheme with the same `encrypt` / `decrypt` interface as `RSAScheme` and `MockKyber`; `seal` (public key only), `MLKEMKeyPair` (Decaps) |
| `key_handoff.py` | Per-patient keys: epoch data key wrapped to the patient, re-wrapped to a doctor at grant time (design in the file's docstring) |
| `benchmark_pqc.py` | Separate benchmark entry point: RSA-2048 vs the paper's mock vs real ML-KEM, primitive and record level, memory, environment |
| `requirements-pqc.txt` | `requirements.txt` + `liboqs-python` (kept apart so the other layers install without it) |
| `tests/test_pqc_real.py`, `tests/test_key_handoff.py`, `tests/test_benchmark_pqc.py` | Conformance, key-flow and benchmark smoke tests |

`tests/test_encryption.py` runs its universal tests (round trip, randomised, tamper, wrong key, truncation, store/fetch) over every scheme,
the real ML-KEM ones included.

### Install liboqs (once)

liboqs-python needs the liboqs C library. It looks in `~/_oqs` and otherwise tries to build it itself, so build it there on purpose:

```bash
pip install cmake ninja                      # if you have no cmake/ninja
git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs.git
cmake -GNinja -S liboqs -B liboqs/build -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
      -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DCMAKE_INSTALL_PREFIX="$HOME/_oqs"
cmake --build liboqs/build --parallel && cmake --install liboqs/build
pip install -r requirements-pqc.txt
```

The same build flags are used in CI. `OQS_USE_OPENSSL=OFF` makes liboqs use its own hashing, so it needs no OpenSSL headers; record this in the paper.

### Run

```bash
python benchmark_pqc.py --quick              # seconds, smoke run
python benchmark_pqc.py                      # full run (5 runs x 1000 records), results in output/pqc/
python benchmark_pqc.py --no-pqc             # baseline schemes only, no liboqs needed
REQUIRE_PQC=1 pytest tests/ -v -rs           # all tests; without REQUIRE_PQC the real-ML-KEM tests are skipped with a warning if liboqs is missing
```

Output in `output/pqc/`: `records.csv` (per scheme: time mean ± 95% CI over runs, p50/p95/p99, throughput, bytes, memory), `primitives.csv`
(KeyGen / Encaps / Decaps), `environment.json` (CPU, OS, versions, commit, seed), `fig_pqc_comparison.png`.

For a publishable run: plug in the charger, close other programs, set the CPU governor to `performance`
(`sudo cpupower frequency-set -g performance`), and run the full benchmark. Numbers are laptop-class and meaningful as ratios on one machine,
not as IoMT-device timings.

CI note: the OpenSSL cross-check tests need OpenSSL 3.5 or newer and are skipped on older runners (the CI log shows the skip reason with `-rs`).
