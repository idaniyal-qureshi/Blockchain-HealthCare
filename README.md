# ZKBlockchain

**A privacy-preserving blockchain framework for healthcare data sharing using post-quantum cryptography and zero-knowledge proofs.**

Final Year Project, FAST-NUCES.

## Problem

Existing simulation-based blockchain architectures for internet hospital systems report strong performance, but their security, privacy,
scalability and reliability claims have not been validated with real cryptographic implementations, distributed network conditions or
realistic physiological data.

The project starts from Hao et al. (PLOS ONE 20(12): e0332887, 2025), *Post-quantum-inspired scalable blockchain architecture for internet
hospital systems with lightweight privacy-preserving access control*. It reproduces that paper as a baseline, then replaces each simulated
part with a real implementation:

| Capability | Baseline paper | This project |
|---|---|---|
| Post-quantum cryptography | Kyber-inspired mock | Standardized PQC (ML-KEM) |
| Access privacy | Hash commitment | Zero-knowledge proof |
| Consensus | Simulated Raft | Multi-node HotStuff |
| Network | Constant delay | WAN delay, loss and failures |
| Sensor data | Synthetic | Framingham dataset |
| Security | Theoretical claims | Empirical threat testing |

The gaps are validation and implementation limits, not claims that the original paper is wrong.

## Repository layout

```
.
├── code/
│   └── v2_components/      Baseline: reimplementation of the paper (Python), split by layer
│       ├── main.py         runs every experiment in order
│       ├── common.py       shared setup and the CFG parameter table
│       ├── sensors.py      1. fault-tolerant sensor ingestion
│       ├── encryption.py   2. RSA-2048 vs Kyber-inspired encryption
│       ├── access_control.py 3. hash-commitment access control
│       ├── consensus.py    4. Raft / PBFT / HotStuff / Tendermint simulator
│       ├── blockchain.py   5. ledger, end-to-end flow, storage, energy
│       ├── report.py       paper's reported values vs. this run
│       ├── README.md       details for the baseline code
│       └── ASSUMPTIONS.md  assumptions and the paper's contradictions
└── docs/                   FYP-I proposal defense slides
```

## Running the baseline

Requires Python 3.10+.

```bash
pip install pycryptodome numpy pandas matplotlib scipy
cd code/v2_components
python main.py
```

A full run takes about 7-10 minutes. Results print to the terminal and the figures are saved to `code/v2_components/output/`.
Each layer can also run on its own (`python sensors.py`, `python consensus.py`, ...). See [code/v2_components/README.md](code/v2_components/README.md).

## Evaluation plan

| Research question | Metric |
|---|---|
| Does real PQC give acceptable performance? | Latency, throughput, ciphertext size |
| Does the privacy mechanism reduce information exposure? | Correctness, identity leakage |
| Does consensus remain usable under realistic networks? | TPS, latency, recovery |
| Does sensor correction generalize beyond synthetic data? | Accuracy, MAE, fault detection |

## Roadmap

- **FYP-I:** literature and gap validation → technical spike / POC → baseline implementation (this repo) → dataset preparation →
  initial experiments → gap implementation → feasibility study
- **FYP-II:** full integration → testbed evaluation → performance benchmarking → final refinement → demonstration and thesis

## Ethics and scope

- Only de-identified, publicly released research data; no live patient data.
- Academic prototype only: no diagnosis, clinical decisions, production deployment or regulatory claims.
- Only proofs and references go on-chain, never raw health records.
- PQC and ZK are used for privacy and security evaluation only.
