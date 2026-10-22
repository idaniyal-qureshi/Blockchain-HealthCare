"""5. Blockchain layer, end-to-end data flow, threat model, storage and energy (Sec. 3.2, 4.5-4.7, 6.12, Figs 1-2, 13)

The end-to-end run wires every layer together as in Fig 1 / Fig 2 and Sec 3.2:
sensors → Fig 2 pipeline → encryption → data packaging (transactions signed by the gateway) → transaction protocol → Raft consensus (rotating leader,
crash faults, a compromised node) → ledger (Eq 12) → smart-contract trigger handler; access requests go through the authorization proof (Algorithm 4),
the patient policy (Eqs 8-10) and consensus, and every grant, revocation and access decision is written to the ledger (audit trail).

Library part: Block, Chain, SmartContractEngine, tx_tag, run_pipeline.
Experiment part: run(PIPE, rsa_r, ky_r, g) (end-to-end run, storage footprint, Eq 13 energy, Fig 13).
Uses sensors.py, encryption.py, access_control.py and consensus.py.
"""
import os, time, hmac, hashlib, json
from dataclasses import dataclass
import numpy as np, pandas as pd, matplotlib.pyplot as plt
from Crypto.Random import get_random_bytes
from common import CFG, display, RESULTS
from sensors import N_S, generate_truth, fig2_pipeline
from encryption import MockKyberHybrid
from access_control import PatientDevice, Requester, HashCommitmentAC, PolicyStore
from consensus import ConsensusCluster

@dataclass
class Block:                                                            # Eq 12: B_i = <H(B_(i-1)), {c_j}, {p_j}, timestamp, metadata>
    index: int; prev_hash: str; ciphertexts: list; proofs: list; timestamp: float; metadata: dict; hash: str = ""
    def compute_hash(self):
        h = hashlib.sha256(f"{self.index}|{self.prev_hash}|{self.timestamp}".encode())
        for c in self.ciphertexts: h.update(c)
        for p in self.proofs: h.update(p)
        h.update(json.dumps(self.metadata, sort_keys=True, default=str).encode()); return h.hexdigest()
    def nbytes(self):
        return 64 + 8 + sum(map(len, self.ciphertexts)) + sum(map(len, self.proofs)) + len(json.dumps(self.metadata, default=str))

class Chain:
    def __init__(self):
        g0 = Block(0, "0" * 64, [], [], 0.0, {"genesis": True}); g0.hash = g0.compute_hash(); self.blocks = [g0]
    def append(self, cts, proofs, meta):
        b = Block(len(self.blocks), self.blocks[-1].hash, cts, proofs, time.time(), meta); b.hash = b.compute_hash(); self.blocks.append(b); return b
    def verify(self):
        return all(b.hash == b.compute_hash() for b in self.blocks) and all(self.blocks[i].prev_hash == self.blocks[i - 1].hash for i in range(1, len(self.blocks)))

class SmartContractEngine:
    """Fig 2 'Smart Contract Trigger Handler': rules evaluated on every committed block; matching rules emit events (automated reaction)."""
    def __init__(self): self.rules, self.events = [], []
    def register(self, name, predicate): self.rules.append((name, predicate))
    def on_commit(self, block):
        for tx in block.metadata.get("tx", []):
            for name, pred in self.rules:
                if pred(tx): self.events.append(dict(rule=name, block=block.index, who=tx.get("pseud")))

GW_KEY = get_random_bytes(32)                                           # ASSUMPTION: gateway key known to the alliance validators
def tx_tag(ct, p, meta): return hmac.digest(GW_KEY, ct + p + json.dumps(meta, sort_keys=True).encode(), "sha256").hex()

def run_pipeline(n_patients=40, steps=20, n_nodes=7, n_crashed=1, compromised=1, fault_rate=0.2, seed=7):
    prng = np.random.default_rng(seed)
    scheme, chain, contracts = MockKyberHybrid(), Chain(), SmartContractEngine()
    cluster = ConsensusCluster("Raft", n_nodes, seed=seed); cluster.crash(n_crashed)
    cluster.compromised = set(prng.choice(np.flatnonzero(cluster.alive), compromised, replace=False).tolist())   # threat A1
    contracts.register("critical-vitals alert", lambda tx: tx.get("alert", False))
    contracts.register("sensor maintenance", lambda tx: tx.get("retx", 0) >= 2 or tx.get("quarantined", 0) > 0)
    contracts.register("access audit", lambda tx: tx.get("event") in ("allow", "deny", "policy_deny"))
    stats_ = dict(rejected_tampered=0, rounds=0)

    def commit(cts, proofs, txs, kind):
        """Data packaging -> transaction protocol -> consensus -> ledger -> triggers. A compromised leader tampers with the first
        record; honest validators check the gateway tag, reject the block, and the next round (new leader) commits it."""
        for _ in range(20):
            def validate(leader):
                prop = [dict(t) for t in txs]; c0 = list(cts)
                if leader in cluster.compromised and c0: c0[0] = b"\x00" + c0[0][1:]                  # A1: tampered record
                return all(t.get("tag") is None or t["tag"] == tx_tag(c, t["p_bytes"], t["meta"]) for t, c in zip(prop, c0 + [b""] * len(prop)))
            r = cluster.run_round(validate=validate); stats_["rounds"] += 1
            if r["committed"]:
                meta_tx = [{k: v for k, v in t.items() if k not in ("p_bytes", "meta")} for t in txs]
                b = chain.append(cts, proofs, dict(kind=kind, term=cluster.term, tx=meta_tx)); contracts.on_commit(b); return b
            stats_["rejected_tampered"] += r["leader"] in cluster.compromised
        raise RuntimeError("no commit")

    audit_buf = []                                                      # audit events are batched into ledger blocks
    def flush_audit():
        if audit_buf: commit([], [], [dict(**e, tag=None) for e in audit_buf], "audit"); audit_buf.clear()

    # 1-2. sensors -> Fig 2 pipeline (one patient is tachycardic so the alert rule fires)
    truth = generate_truth(n_patients, prng); truth[5] = 135.0
    keys = [[os.urandom(16) for _ in range(N_S)] for _ in range(n_patients)]
    pipe = fig2_pipeline(np.repeat(truth[:, None], steps, 1), fault_rate, prng, keys)
    # consent: each patient device issues tokens to hospA and defines a read policy on its EHR
    ac, ps = HashCommitmentAC(audit_sink=audit_buf.append), PolicyStore(audit_sink=audit_buf.append)
    devices = [PatientDevice(f"patient-{i:04d}") for i in range(n_patients)]
    hospA, pol_tok, where = {}, {}, {}
    for dv in devices:
        p, s = dv.issue_token("read_ehr"); ac.enroll(dv.pseud, "read_ehr", p); hospA[dv.pseud] = Requester("hospA", s)
        pol_tok[dv.pseud] = ps.define(dv, "hospA", "doctor", "EHR", "read", time.time() + 3600)
    flush_audit()
    # 3. encryption + data packaging: one record per patient per minute (20 readings)
    pending = []
    for i, dv in enumerate(devices):
        vals = pipe["est"][i]; ok = np.isfinite(vals)
        rec = dict(pid=dv.pseud, hr=[round(float(v), 1) if np.isfinite(v) else None for v in vals])
        meta = dict(pseud=dv.pseud, ts=time.time(), alert=bool(np.any((vals[ok] < CFG["ALERT_RANGE"][0]) | (vals[ok] > CFG["ALERT_RANGE"][1]))),
                    retx=int(pipe["retx"][i].sum()), quarantined=int(pipe["quarantined"][i].sum()))
        ct = scheme.encrypt(json.dumps(rec).encode()); p_b = ac.commit[(dv.pseud, "read_ehr")]
        pending.append((ct, p_b, dict(meta, meta=meta, p_bytes=p_b, tag=tx_tag(ct, p_b, meta))))
    # 5-6. leader proposes, quorum commits (Eq 12 block = ciphertexts + proofs + metadata)
    for b in range(0, n_patients, 10):
        chunk = pending[b:b + 10]
        blk = commit([c for c, _, _ in chunk], [p for _, p, _ in chunk], [t for _, _, t in chunk], "records")
        for j, (_, _, t) in enumerate(chunk): where[t["pseud"]] = (blk.index, j)
    print(f"{len(chain.blocks) - 1} blocks committed with {n_crashed}/{n_nodes} nodes crashed and {compromised} compromised; "
          f"blocks rejected because a compromised leader tampered with them: {stats_['rejected_tampered']}; chain valid = {chain.verify()}")

    # 4-7. access request: authorization proof (Alg 4) + patient policy (Eqs 8-10) + consensus -> decrypt
    def request_access(requester, dv, policy_token, resource="EHR", action="read", corrupt_first=0):
        ok = requester.access(ac, dv.pseud, "read_ehr", corrupt_first=corrupt_first) == 1
        ok = ok and ps.check(dv.pseud, policy_token, resource, action)
        flush_audit()                                                   # decision written to the ledger through consensus
        if not ok: return "DENIED"
        bi, j = where[dv.pseud]; return scheme.decrypt(chain.blocks[bi].ciphertexts[j]).decode()[:60] + "..."
    d3 = devices[3]
    print("Valid proof + policy               ->", request_access(hospA[d3.pseud], d3, pol_tok[d3.pseud]))
    print("Valid, 2 corrupted transmissions   ->", request_access(hospA[d3.pseud], d3, pol_tok[d3.pseud], corrupt_first=2))
    print("Wrong secret (other hospital)      ->", request_access(Requester("hospB", os.urandom(32)), d3, pol_tok[d3.pseud]))
    print("Valid proof, write not permitted   ->", request_access(hospA[d3.pseud], d3, pol_tok[d3.pseud], action="write"))
    ps.revoke(d3, "hospA", "EHR"); flush_audit()
    print("After policy revocation            ->", request_access(hospA[d3.pseud], d3, pol_tok[d3.pseud]))
    ev = pd.Series([e["rule"] for e in contracts.events]).value_counts()
    print("Smart-contract trigger events:", dict(ev))
    audit_blocks = [b for b in chain.blocks if b.metadata.get("kind") == "audit"]
    leaked = any(dv.pid in json.dumps(b.metadata, default=str) for b in chain.blocks for dv in devices)
    print(f"Audit trail on-chain: {sum(len(b.metadata['tx']) for b in audit_blocks)} events in {len(audit_blocks)} blocks; "
          f"patient identities on the ledger: {'YES' if leaked else 'none'}")
    good = chain.verify()
    chain.blocks[1].ciphertexts = [b"tampered"] + chain.blocks[1].ciphertexts[1:]
    print(f"Chain valid before tampering: {good}; after tampering with a stored record: {chain.verify()}")
    rec_blocks = [b for b in chain.blocks if b.metadata.get("kind") == "records"]
    return dict(bytes_per_record=sum(b.nbytes() for b in rec_blocks) / n_patients, n_blocks=len(chain.blocks) - 1)


def run(PIPE, rsa_r, ky_r, g):
    """End-to-end run, storage footprint and Eq 13 energy model (Fig 13).
    PIPE: sensors.run()["PIPE"]; rsa_r, ky_r: encryption.run(); g: consensus.run()["g"]. Needs RESULTS["proof_gen_ms"] from access_control.run()."""
    PIPE_OUT = run_pipeline()

    # --- storage footprint (abstract: ~15 MB/day) ---
    bpr = PIPE_OUT["bytes_per_record"]; P_ = CFG["N_PATIENTS"]
    per_min = bpr * P_ * 1440 / 1e6
    print(f"Ledger storage: {bpr:.0f} B per patient-minute record (20 readings) -> {per_min:,.0f} MB/day for {P_} patients. "
          f"A 15 MB/day footprint would allow only one such record per patient every {bpr * P_ * 1440 / 15e6:.0f} min.")
    RESULTS["storage_mb_day"] = per_min

    # --- Sec 4.6, Eq 13: E_tx = n_enc*e_enc + n_cons*e_cons + n_re*e_re, with measured inputs ---
    uj_per_ms = CFG["E_CRYPTO_UJ"] / rsa_r["enc"].mean()                    # ASSUMPTION: 30.2 uJ = one RSA-2048 encryption -> energy per ms of CPU
    e_rsa, e_ky, e_pr = CFG["E_CRYPTO_UJ"], uj_per_ms * ky_r["enc"].mean(), uj_per_ms * RESULTS["proof_gen_ms"]
    m_pbft, m_raft = g("PBFT", CFG["ENERGY_N"], "msgs") / CFG["BLOCK_SIZE"], g("Raft", CFG["ENERGY_N"], "msgs") / CFG["BLOCK_SIZE"]
    fr_e = int(CFG["ENERGY_FAULT_RATE"] * 100)
    re_base, re_prop = PIPE.loc[fr_e, "baseline_retx_per_group"], PIPE.loc[fr_e, "retx_per_group"]
    energy = pd.DataFrame({"Baseline (RSA + PBFT, no correction)": [e_rsa, 0.0, m_pbft * CFG["E_MSG_UJ"], re_base * CFG["E_MSG_UJ"]],
                           "Proposed (Kyber-inspired + proof + Raft + Fig 2 pipeline)": [e_ky, e_pr, m_raft * CFG["E_MSG_UJ"], re_prop * CFG["E_MSG_UJ"]]},
                          index=["encryption", "proof generation", "consensus messages", "retransmissions"]).T
    energy["total_uJ_per_tx"] = energy.sum(axis=1)
    print(f"Energy per transaction, Eq 13 (N = {CFG['ENERGY_N']} nodes, fault rate {fr_e}%, e_re = one message):"); display(energy.round(2))
    base_E, prop_E = energy.total_uJ_per_tx.iloc[0], energy.total_uJ_per_tx.iloc[1]
    RESULTS["energy"] = 100 * (1 - prop_E / base_E)
    fig, ax = plt.subplots(figsize=(5, 3.8))                                # Fig 13
    b = ax.bar(["Baseline\n(PBFT + RSA)", "Proposed\n(Raft + Kyber-inspired)"], [1.0, prop_E / base_E], color=["grey", "green"]); ax.bar_label(b, fmt="%.3f")
    ax.set_ylabel("Normalized energy per transaction"); ax.set_title("Estimated node energy per transaction (cf. Fig 13)")
    plt.savefig("fig13_energy.png", bbox_inches="tight"); plt.show()
    return dict(PIPE_OUT=PIPE_OUT, energy=energy)


if __name__ == "__main__":
    print("blockchain.py depends on every earlier part; running main.py instead.")
    import main; main.main()
