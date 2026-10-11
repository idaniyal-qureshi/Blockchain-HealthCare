"""4. Consensus (Sec. 4.4, Algorithm 5, Eq 11, Sec. 5.5, 6.2-6.4, 6.10, 6.11, Figs 4-6, 12, Table 3)

A message-level simulator under the paper's synchronous constant-delay network: every message takes `HOP_DELAY_MS`; each node has one CPU that
sends messages one after another and processes incoming messages in arrival order (send/process costs with small random jitter). Latency is the time
until the leader knows the block is committed. Each protocol runs `CONS_ROUNDS = 100` rounds per network size (Table 2) on an executable cluster with
crash faults, per-node logs and a commit index.

* Raft (Algorithm 5): `L ~ U(N∖F)` every round (rotating leader, Sec 3.1); AppendEntries to all; commit iff `|Q| ≥ ⌊N/2⌋+1` (Eq 11), else NULL.
  Modes (Sec 6.2): normal; failover (RequestVote election with a randomised timeout every 10 rounds); congestion (hop delay ×3).
* PBFT: pre-prepare, all-to-all prepare, all-to-all commit, quorum 2f+1, MAC-authenticated. Simulated at 4/10/20 nodes and extrapolated (as in the paper).
* HotStuff: three leader-collected QCs (prepare, pre-commit, commit) + decide; signed votes.
* Tendermint: propose, all-to-all prevote, all-to-all precommit (as in the Tendermint protocol); signed votes.

Throughput = transactions per block ÷ block latency (blocks committed one after another).

Library part: the simulator and ConsensusCluster (used again by blockchain.py).
Experiment part: run_availability() (Eq 11 / Lemma 2) and run() (benchmark, Figs 4-6, 12, Table 3).
"""
import time, zlib
import numpy as np, pandas as pd, matplotlib.pyplot as plt
from scipy import stats
from scipy.optimize import nnls
from common import CFG, ci95, fmt, display, RESULTS

def _cpu(rng, base, shape):                                            # per-message CPU time with log-normal jitter (ASSUMPTION)
    s = np.sqrt(np.log(1 + CFG["JITTER_CV"] ** 2)); return base * rng.lognormal(-s * s / 2, s, shape)

def _serial(arrivals, costs, free_at):
    """One CPU processing messages in arrival order: c_k = max(a_k, c_(k-1)) + p_k, vectorised on the last axis (inf = never arrives)."""
    a = np.maximum(np.sort(arrivals, axis=-1), np.asarray(free_at)[..., None])
    S = np.cumsum(costs, -1)
    return S + np.maximum.accumulate(a - (S - costs), axis=-1)

def leader_phase(rng, t0, n, leader, alive, needed, d, vote_cost):
    """Leader sends to the n-1 others one after another; each live node processes and replies; the leader processes replies in
    arrival order. Returns (time the `needed`-th reply is processed, messages)."""
    m = n - 1; others = np.delete(np.arange(n), leader)
    send_done = t0 + CFG["SEND_COST_MS"] * rng.permutation(np.arange(1, m + 1))
    live = alive[others]
    reply_at = np.where(live, send_done + d + _cpu(rng, CFG["PROC_COST_MS"], m) + CFG["SEND_COST_MS"] + d, np.inf)
    if needed <= 0: return t0 + CFG["SEND_COST_MS"] * m, m
    done = _serial(reply_at, _cpu(rng, vote_cost, m), t0 + CFG["SEND_COST_MS"] * m)
    return float(done[needed - 1]), m + int(live.sum())

def all_to_all_phase(rng, start, alive, needed_others, d, vote_cost):
    """Every participating node broadcasts its vote to all others (one send after another), then processes incoming votes in arrival order.
    start[i] = when node i enters the phase (inf = never). Returns (time each node has processed `needed_others` votes, messages)."""
    n = len(start); part = alive & np.isfinite(start)
    pos = rng.permuted(np.tile(np.arange(1, n + 1, dtype=float), (n, 1)), axis=1)     # send order of each sender
    arr = (start[:, None] + CFG["SEND_COST_MS"] * pos + d).T                          # arr[i, j]: vote from j reaches i
    arr[:, ~part] = np.inf; np.fill_diagonal(arr, np.inf)
    done = _serial(arr, _cpu(rng, vote_cost, (n, n)), start + CFG["SEND_COST_MS"] * (n - 1))
    t = np.where(part, done[:, needed_others - 1], np.inf)
    return t, (n - 1) * int(part.sum())

def protocol_round(proto, n, alive, leader, rng, d):
    """Latency (ms, inf = no commit) and message count of one block for the given protocol."""
    if proto == "Raft":
        return leader_phase(rng, 0.0, n, leader, alive, (n // 2 + 1) - 1, d, CFG["PROC_COST_MS"])   # Eq 11 quorum incl. leader
    f = (n - 1) // 3; q = 2 * f + 1
    if proto == "HotStuff":
        t, msgs = 0.0, 0
        for _ in range(3):                                              # prepare, pre-commit, commit QCs (signed votes)
            t, m = leader_phase(rng, t, n, leader, alive, q - 1, d, CFG["PROC_COST_MS"] + CFG["SIG_VERIFY_MS"]); msgs += m
            if not np.isfinite(t): break
        return t, msgs + (n - 1)                                        # + decide broadcast
    vote = CFG["PROC_COST_MS"] + (CFG["SIG_VERIFY_MS"] if proto == "Tendermint" else 0.0)   # PBFT: MAC authenticators; Tendermint: signatures
    others = np.delete(np.arange(n), leader); start = np.full(n, np.inf)
    start[others] = CFG["SEND_COST_MS"] * rng.permutation(np.arange(1, n)) + d + _cpu(rng, CFG["PROC_COST_MS"], n - 1)   # pre-prepare / proposal
    start[leader] = CFG["SEND_COST_MS"] * (n - 1); start[~alive] = np.inf
    t1, m1 = all_to_all_phase(rng, start, alive, q - 1, d, vote)       # prepare / prevote
    t2, m2 = all_to_all_phase(rng, t1, alive, q - 1, d, vote)          # commit / precommit
    return float(t2[leader]), (n - 1) + m1 + m2

class ConsensusCluster:
    """Executable cluster for Algorithm 5 (Raft) and the BFT baselines: crash faults, rotating leader, per-node logs, commit index."""
    def __init__(self, proto, n, seed=0, mode="normal"):
        self.proto, self.n, self.mode, self.rng = proto, n, mode, np.random.default_rng(seed)
        self.alive, self.log_len = np.ones(n, bool), np.zeros(n, int)
        self.commit_index = self.term = self.rounds = 0; self.compromised = set()
    @property
    def quorum(self): return self.n // 2 + 1 if self.proto == "Raft" else 2 * ((self.n - 1) // 3) + 1   # Eq 11 / BFT 2f+1
    def crash(self, k):
        self.alive[self.rng.choice(np.flatnonzero(self.alive), k, replace=False)] = False
    def run_round(self, validate=None):
        """Alg 5: L ~ U(N\\F); B <- propose(T, L); collect accepts from N\\F; commit iff |Q| >= quorum, else NULL.
        validate(leader) -> False means honest nodes reject the proposed block (e.g. tampered by a compromised leader)."""
        healthy = np.flatnonzero(self.alive)
        if len(healthy) < self.quorum: return dict(committed=False, latency=np.nan, msgs=0, leader=None)
        d = CFG["HOP_DELAY_MS"] * (CFG["CONGESTION_FACTOR"] if self.mode == "congestion" else 1.0)
        leader = int(self.rng.choice(healthy)); self.term += 1; extra, msgs = 0.0, 0
        if self.proto == "Raft" and self.mode == "failover" and self.rounds % CFG["FAILOVER_EVERY"] == 0:
            tv, mv = leader_phase(self.rng, 0.0, self.n, leader, self.alive, self.quorum - 1, d, CFG["PROC_COST_MS"])   # RequestVote
            extra, msgs = self.rng.uniform(*CFG["ELECTION_TIMEOUT_MS"]) + tv, mv
        lat, m = protocol_round(self.proto, self.n, self.alive, leader, self.rng, d); msgs += m; self.rounds += 1
        if validate is not None and not validate(leader): lat = np.inf
        self.log_len[self.alive] += 1                                   # followers append the proposed entry
        if np.isfinite(lat): self.commit_index += 1; return dict(committed=True, latency=extra + lat, msgs=msgs, leader=leader)
        self.log_len[self.alive] -= 1                                   # uncommitted entry truncated
        return dict(committed=False, latency=np.nan, msgs=msgs, leader=leader)


def run_availability():
    """Crash-fault availability (Eq 11, Lemma 2)."""
    for proto, n, k in [("Raft", 9, 4), ("Raft", 9, 5), ("Raft", 1000, 499), ("Raft", 1000, 500), ("PBFT", 10, 3), ("PBFT", 10, 4)]:
        c = ConsensusCluster(proto, n, seed=1); c.crash(k); r = c.run_round()
        print(f"{proto:5s} N={n:4d}, crashed={k:3d} (quorum {c.quorum}) -> {'committed' if r['committed'] else 'no quorum, NULL'}")


def run():
    """Benchmark: 100 rounds per (protocol, mode, size), PBFT extrapolation, Figs 4-6, 12 and Table 3.
    Returns cons (per-round rows), cagg (aggregates) and g(p, n, col) (lookup used by the energy model)."""
    cases = [("Raft", "normal"), ("Raft", "failover"), ("Raft", "congestion"), ("HotStuff", "normal"), ("Tendermint", "normal"), ("PBFT", "normal")]
    if CFG["PBFT_FULL_SCALE"]: cases.append(("PBFT", "full-scale sim"))
    rows = []; t_start = time.time()
    for proto, mode in cases:
        sizes = CFG["PBFT_SIZES"] if (proto, mode) == ("PBFT", "normal") else sorted(set(CFG["RAFT_SIZES"]) | {20})   # 20: common size for Table 3
        label = proto if mode == "normal" else f"{proto} ({mode})"
        for n in sizes:
            cl = ConsensusCluster(proto, n, seed=zlib.crc32(f"{proto}|{mode}|{n}".encode()), mode=mode)
            for _ in range(CFG["CONS_ROUNDS"]):
                r = cl.run_round(); rows.append(dict(protocol=label, nodes=n, latency_ms=r["latency"], messages=r["msgs"],
                                                     tps=CFG["BLOCK_SIZE"] / (r["latency"] / 1000)))
    print(f"Consensus simulation: {len(rows)} rounds in {time.time() - t_start:.0f} s")
    cons = pd.DataFrame(rows)
    cagg = cons.groupby(["protocol", "nodes"]).agg(lat=("latency_ms", "mean"), lat_ci=("latency_ms", ci95), msgs=("messages", "mean"),
                                                   tps=("tps", "mean"), tps_ci=("tps", ci95)).reset_index()

    # PBFT beyond 20 nodes: extrapolation (paper: "extrapolated from the literature"; here: non-negative quadratic fit to the simulated points)
    pb = cagg[cagg.protocol == "PBFT"]
    if True:
        A = lambda N: np.vstack([np.ones(len(N)), N, np.asarray(N, float) ** 2]).T          # a + bN + cN^2 with a, b, c >= 0
        c_lat = nnls(A(pb.nodes.values), pb.lat.values)[0]; c_msg = nnls(A(pb.nodes.values), pb.msgs.values)[0]
        ext = pd.DataFrame(dict(protocol="PBFT (extrapolated)", nodes=CFG["RAFT_SIZES"], lat=A(CFG["RAFT_SIZES"]) @ c_lat,
                                lat_ci=np.nan, msgs=A(CFG["RAFT_SIZES"]) @ c_msg, tps_ci=np.nan))
        ext["tps"] = CFG["BLOCK_SIZE"] / (ext.lat / 1000); cagg = pd.concat([cagg, ext], ignore_index=True)
    show = cagg[cagg.nodes.isin([20, 100, 1000])].copy()
    show["latency_ms"] = [fmt(a, b) if np.isfinite(b) else f"{a:.2f} (extrap.)" for a, b in zip(show.lat, show.lat_ci)]
    show["TPS"] = [fmt(a, b, 1) if np.isfinite(b) else f"{a:.1f} (extrap.)" for a, b in zip(show.tps, show.tps_ci)]
    print("Latency per block (ms), messages per block and throughput (mean ± 95% CI over 100 rounds)")
    display(show.pivot(index="protocol", columns="nodes", values=["latency_ms", "msgs", "TPS"]))

    def g(p, n, col="lat"):
        s = cagg[(cagg.protocol == p) & (cagg.nodes == n)][col]; return float(s.iloc[0]) if len(s) else np.nan
    PB_1000 = "PBFT (extrapolated)"  # as in the paper
    raft20 = cons[(cons.protocol == "Raft") & (cons.nodes == 20)]
    slope = np.polyfit(cagg[(cagg.protocol == "Raft") & (cagg.nodes >= 200)].nodes, cagg[(cagg.protocol == "Raft") & (cagg.nodes >= 200)].lat, 1)[0]
    RESULTS.update(pbft_sim_1000=g("PBFT (full-scale sim)", 1000), pbft_sim_tps=g("PBFT (full-scale sim)", 1000, "tps"), raft_1000=g("Raft", 1000), raft_fo=g("Raft (failover)", 1000), raft_cg=g("Raft (congestion)", 1000), pbft_1000=g(PB_1000, 1000),
                   hs_1000=g("HotStuff", 1000), tm_1000=g("Tendermint", 1000), raft_tps=g("Raft", 1000, "tps"), pbft_tps=g(PB_1000, 1000, "tps"),
                   hs_tps=g("HotStuff", 1000, "tps"), tm_tps=g("Tendermint", 1000, "tps"), raft_slope=slope, pbft_20=g("PBFT", 20), raft_20=g("Raft", 20))

    # ---------------- Figs 4, 5, 6, 12 ----------------
    fig, ax = plt.subplots(figsize=(7.5, 4.2))                              # Fig 4
    for p in ["Raft", "Raft (failover)", "Raft (congestion)", "HotStuff", "Tendermint", "PBFT", "PBFT (extrapolated)", "PBFT (full-scale sim)"]:
        s = cagg[cagg.protocol == p].sort_values("nodes")
        if len(s): ax.errorbar(s.nodes, s.lat, yerr=s.lat_ci.fillna(0), marker="o", ms=3, capsize=2, ls="--" if "extrap" in p else (":" if "full" in p else "-"), label=p)
    ax.set_yscale("log"); ax.set_xlabel("Number of nodes"); ax.set_ylabel("Consensus time (ms)"); ax.grid(alpha=.3, which="both"); ax.legend(fontsize=7)
    ax.set_title("Consensus time vs nodes, all protocols (cf. Fig 4)"); plt.savefig("fig04_consensus_all.png", bbox_inches="tight"); plt.show()
    fig, ax = plt.subplots(figsize=(7, 4))                                  # Fig 5
    for p in ["PBFT (extrapolated)", "PBFT (full-scale sim)", "Raft", "HotStuff", "Tendermint"]:
        s = cagg[(cagg.protocol == p) & cagg.nodes.isin([10, 50, 100, 500, 1000])].sort_values("nodes"); ax.plot(s.nodes, s.lat, marker="o", label=p)
    ax.set_xlabel("Number of nodes"); ax.set_ylabel("Latency (ms)"); ax.grid(alpha=.3); ax.legend(); ax.set_title("Consensus latency vs number of nodes (cf. Fig 5)")
    plt.savefig("fig05_consensus_latency.png", bbox_inches="tight"); plt.show()
    fig, ax = plt.subplots(figsize=(7, 4))                                  # Fig 6
    s = cagg[(cagg.protocol == "Raft") & (cagg.nodes >= 200)].sort_values("nodes")
    ax.errorbar(s.nodes, s.lat, yerr=s.lat_ci, marker="o", capsize=3, color="green", label=f"Raft (slope {slope:.3f} ms/node)")
    ax.set_xlabel("Number of nodes"); ax.set_ylabel("Consensus time (ms)"); ax.grid(alpha=.3); ax.legend(); ax.set_title("Raft scaling with node count (cf. Fig 6)")
    plt.savefig("fig06_raft_scaling.png", bbox_inches="tight"); plt.show()
    fig, ax = plt.subplots(figsize=(7, 4))                                  # Fig 12
    labs = ["Raft", PB_1000, "HotStuff", "Tendermint"]; vals = [g(p, 1000, "tps") for p in labs]
    b = ax.bar([l.replace(" (extrapolated)", "\n(extrap.)") for l in labs], vals, color=["green", "red", "blue", "orange"]); ax.bar_label(b, fmt="%.1f")
    ax.set_ylabel("Transactions per second"); ax.set_title(f"Throughput at 1000 nodes, block = {CFG['BLOCK_SIZE']} tx (cf. Fig 12)")
    plt.savefig("fig12_throughput.png", bbox_inches="tight"); plt.show()

    # ---------------- Table 3: statistical validation (Welch t-tests on per-round TPS) ----------------
    def tps_of(p, n): return cons[(cons.protocol == p) & (cons.nodes == n)].tps.dropna().values
    t3 = []
    for n, ref, protos in [(20, "PBFT", ["Raft", "HotStuff", "Tendermint", "PBFT"]), (1000, "Raft", ["Raft", "HotStuff", "Tendermint"] + (["PBFT (full-scale sim)"] if CFG["PBFT_FULL_SCALE"] else []))]:
        for p in protos:
            a = tps_of(p, n); pv = stats.ttest_ind(a, tps_of(ref, n), equal_var=False).pvalue if p != ref else np.nan
            t3.append(dict(nodes=n, protocol=p, mean_TPS=round(a.mean(), 1), CI95=f"[{a.mean() - ci95(a):.1f}, {a.mean() + ci95(a):.1f}]",
                           mean_latency_ms=round(1000 * CFG["BLOCK_SIZE"] / a.mean(), 2), **{"p-value vs " + ref: pv}))
    T3 = pd.DataFrame(t3)
    print("Table 3 analogue: mean TPS, 95% CI and Welch p-value against the reference protocol at that size")
    display(T3.set_index(["nodes", "protocol"]))
    return dict(cons=cons, cagg=cagg, g=g, T3=T3)


if __name__ == "__main__":
    run_availability()
    run()
