"""Shared setup for every component: imports, plot settings, seed, helpers (H, ci95, fmt) and the CFG parameter table.

Hao et al. (PLOS ONE 20(12): e0332887, 2025): paper implementation, v2
*Post-quantum-inspired scalable blockchain architecture for internet hospital systems with lightweight privacy-preserving access control*

Conventions
* `# ASSUMPTION` marks a value or formula the paper does not give. All of them are listed in ASSUMPTIONS.md.
* `# RESOLVES` marks a place where the paper contradicts itself; the comment says which reading the code follows and why.
* All results are reported as mean ± 95% CI over repeated runs/rounds (Sec. 5.6). Plots are saved at 400 DPI (Table 2).

Requires: pip install pycryptodome numpy pandas matplotlib scipy
"""
import os, time, hmac, hashlib, json, struct, warnings, tracemalloc, zlib
from dataclasses import dataclass, field
import numpy as np, pandas as pd, matplotlib.pyplot as plt
from scipy import stats
from scipy.optimize import nnls
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
try:
    from IPython.display import display
except ImportError:
    display = print
try:                                                                  # True inside Jupyter/Colab, False for `python main.py`
    from IPython import get_ipython
    IN_NOTEBOOK = get_ipython() is not None and "IPKernelApp" in get_ipython().config
except ImportError:
    IN_NOTEBOOK = False

warnings.filterwarnings("ignore", category=RuntimeWarning)
pd.set_option("display.width", 220); pd.set_option("display.max_columns", 40)
plt.rcParams["savefig.dpi"] = 400                                     # Table 2: all plots at 400 DPI
SEED = 42
rng = np.random.default_rng(SEED)
H = lambda b: hashlib.sha256(b).digest()                              # SHA-256 (Sec 4.3, Eq 17)

def ci95(a):
    """Half-width of the 95% t-confidence interval of the mean (Sec 5.6 / 6.11)."""
    a = np.asarray(a, float); a = a[np.isfinite(a)]
    return float(stats.t.ppf(0.975, len(a) - 1) * a.std(ddof=1) / np.sqrt(len(a))) if len(a) > 1 else 0.0
def fmt(m, c, nd=2): return f"{m:.{nd}f} ± {c:.{nd}f}"

CFG = dict(
    # ---------------- From the paper ----------------
    N_PATIENTS=1000, N_SENSORS=5, N_STEPS=200, READ_INTERVAL_S=3,  # Sec 5.2 / Table 2: 5 sensors, 1 reading / 3 s, 10 min
    SIGMA=0.5,                     # Sec 5.2: delta ~ N(0, 0.5).  ASSUMPTION: 0.5 is the standard deviation
    SPOOF=(15, 25),                # Sec 5.2: spoofs of +-15 or +-25 (Eq 2: "fixed amplitude"; Table 2's "+-15 to +-25" read the same way)
    ACC_TOL=1.0,                   # Eq 16: correct if within +-1 unit
    FAULT_RATES=[0.05, 0.10, 0.15, 0.20, 0.30],   # RESOLVES: Sec 5.3 lists 15%, Table 2 / figures omit it -> all five are run
    CRYPTO_ROUNDS=100,             # Sec 5.4: 100 message samples per scheme
    AUTH_ROUNDS=500,               # Table 2: 100-500 requests -> upper value
    BLOCK_SIZE=20,                 # Table 2: 10-20 transactions per block
    RAFT_SIZES=[10, 50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000],   # Sec 6.2-6.4 (100-1000) + Fig 5 sizes (10, 50)
    PBFT_SIZES=[4, 10, 20],        # Sec 5.5 / 6.2: PBFT simulated only up to 20 nodes, larger sizes extrapolated
    CONS_ROUNDS=100,               # Table 2: 100 terms per node group
    FAILOVER_EVERY=10,             # Sec 6.2: leader re-election every 10 rounds
    E_CRYPTO_UJ=30.2, E_MSG_UJ=16.5,   # Sec 4.6: energy per cryptographic op / per consensus message
    N_RUNS=5,                      # Sec 5.6: "multiple runs"
    # ---------------- ASSUMPTIONS (paper gives no value) ----------------
    P_MISSING=0.3,                 # share of injected faults that are dropouts (rest are spoofs)
    P_EXTERNAL_SPOOF=0.5,          # share of spoofs injected by an outside attacker (threat A2, no sensor key) vs. a faulty sensor
    EPS=1.5,                       # Algorithm 1/2 outlier tolerance = 3 sigma; also the variance threshold of the error-detection layer
    SEVERE_DEV=6.0,                # fault classification: deviation above this = severe (below = minor)
    ETA_WINDOW=20,                 # Algorithm 2 fault estimate: moving window in time steps
    RETRY_K=3,                     # Algorithm 4 retry limit k, also the Fig 2 "retry if failed" limit
    AUTH_WINDOW_S=30.0,            # Sec 4.3.2 acceptable timestamp window
    TOKEN_CHAIN_LEN=1000,          # one-time authorization tokens issued per consent (see access_control.py)
    HOP_DELAY_MS=1.0,              # synchronous constant network delay (paper: "constant-delay", value not given)
    SEND_COST_MS=0.01, PROC_COST_MS=0.04,   # per-message send / process CPU time at a node
    SIG_VERIFY_MS=0.05,            # extra per-vote cost where votes are signed (HotStuff, Tendermint)
    JITTER_CV=0.2,                 # coefficient of variation of per-message CPU time (gives run-to-run variance)
    CONGESTION_FACTOR=3.0,         # Sec 6.2 "artificial message delay": hop delay x3
    ELECTION_TIMEOUT_MS=(150, 300),# Raft's randomised election timeout (Ongaro & Ousterhout default range)
    ENERGY_N=20,                   # node count used for Eq 13 (the only size where PBFT is simulated)
    ENERGY_FAULT_RATE=0.20,        # sensor fault rate used for the retransmission term of Eq 13
    ALERT_RANGE=(50, 120),         # smart-contract alert rule for heart rate (bpm)
    PBFT_FULL_SCALE=True,          # also simulate PBFT up to 1000 nodes as a check on the paper's extrapolation (False = paper only)
)
RESULTS, STATS = {}, {}
