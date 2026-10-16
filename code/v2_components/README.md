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
