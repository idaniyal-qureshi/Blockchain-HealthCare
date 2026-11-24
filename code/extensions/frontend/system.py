"""Interactive baseline system behind the web front end.

Assembles the paper-faithful base components (code/v2_components, unchanged) into one stateful system that the UI can drive step
by step. The flow is the base's blockchain.run_pipeline (Sec 3.2): sensor records -> encryption at the edge -> gateway-tagged
transactions -> Raft consensus (crashed and compromised nodes) -> ledger (Eq 12) -> smart-contract triggers; access requests go
through the authorization proof (Algs 3-4), the patient policy (Eqs 8-10) and consensus, and every decision is written to the ledger.

Two data sources feed the same pipeline:
  * "synthetic": the base's simulated sensors (sensors.edge_records), as in the paper;
  * "wildppg":   real WildPPG recordings (code/extensions/data_layer, fig2_wildppg.edge_records), with the ECG heart rate as truth.

Nothing here changes base behaviour: the paper's flaws (token sent in the clear, ledger-copied policy token) are reproduced.
"""
import os, sys, json, time, hashlib, pathlib, threading
os.environ.setdefault("MPLBACKEND", "Agg")                       # base modules import pyplot; never open windows from a server

HERE = pathlib.Path(__file__).resolve().parent
CODE = HERE.parents[1]                                            # .../code
BASE_DIR = CODE / "v2_components"
DATA_DIR = CODE / "extensions" / "data_layer"
for p in (str(BASE_DIR), str(DATA_DIR)):
    if p not in sys.path: sys.path.insert(0, p)

import numpy as np
import sensors, encryption, consensus, blockchain as bc, access_control as acm
from access_control import PatientDevice, Requester, HashCommitmentAC, PolicyStore, RBACContract, identity_leakage
from common import CFG, H, ci95

PERMISSION = "read_ehr"
MAX_REQUESTS, MAX_CONSENSUS_LOG, MAX_POLICIES_PER_PATIENT = 5000, 500, 50   # in-memory caps (stress test: unbounded growth)
LOG_PAGE, LEDGER_PAGE, HISTORY_PAGE = 500, 300, 300           # rows sent per page (stress test: multi-MB responses)                                                    # rows of the access log sent to the hospital portal
CHUNK = 20                       # sensor records per ledger transaction (base run_pipeline: one record of 20 readings per patient)
TX_PER_BLOCK = 10                # base run_pipeline commits 10 records per block
POLICY_TTL_S = 24 * 3600.0
HOSPITALS = ("hospA", "hospB")


def wildppg_available():
    """(available, participant names). Needs the extracted window CSVs from the data layer; never downloads anything."""
    try:
        import wildppg
        files = sorted(wildppg.DATA_DIR.glob(f"*_w{wildppg.WIN_S}_{wildppg.PPG_METHOD}.csv"))
        return bool(files), [f.name.split("_")[2] for f in files]
    except Exception:
        return False, []


def load_records(source, n_patients, n_steps):
    """{label: [record]} in the base edge-record format, {label: truth list or None}, and a description of the source."""
    if source == "synthetic":
        recs = sensors.edge_records(n_patients=n_patients, n_steps=n_steps)
        return ({f"patient-{pid + 1:04d}": r for pid, r in recs.items()}, {f"patient-{pid + 1:04d}": None for pid in recs},
                f"Simulated sensors (paper Sec 5.2): 5 sensors, {int(sensors.EDGE_FAULT_RATE * 100)}% injected faults, "
                f"1 reading / {CFG['READ_INTERVAL_S']} s")
    if source == "wildppg":
        ok, _ = wildppg_available()
        if not ok: raise RuntimeError("WildPPG window files not found in code/extensions/data_layer/data/wildppg")
        import main_wildppg, fig2_wildppg
        parts, skipped = main_wildppg.load_parts(log=lambda *_: None)
        recs, truth, used = {}, {}, 0
        for name, df in parts:                                  # one participant at a time, so one unusable block does not stop the rest
            if used >= n_patients: break
            try:
                r, t = fig2_wildppg.edge_records([(name, df)], n_steps=n_steps)
            except ValueError:
                continue
            label = f"wildppg-{name.split('_')[2]}"
            recs[label] = [dict(x, pid=label) for x in r[name]]
            truth[label] = [None if v is None or not np.isfinite(v) else round(float(v), 2) for v in t[name]]   # ECG gaps -> null (JSON)
            used += 1
        if not recs: raise RuntimeError("no WildPPG participant has a usable block of consecutive windows")
        return (recs, truth, f"Real WildPPG recordings: 4 body-worn PPG sensors, ECG heart rate as truth, 8-s windows, "
                             f"{int(sensors.EDGE_FAULT_RATE * 100)}% injected faults (noisy-ECG participants left out)")
    raise ValueError(f"unknown source {source!r}")


class DemoSystem:
    """One running instance of the baseline system. All public methods return JSON-ready dicts."""

    def __init__(self, source="synthetic", n_patients=8, n_steps=100, n_nodes=7, crashed=1, compromised=1, seed=7):
        self.lock = threading.RLock()
        self.cfg = dict(source=source, n_patients=n_patients, n_steps=n_steps, n_nodes=n_nodes, crashed=crashed,
                        compromised=compromised, seed=seed)
        self._build()

    # ------------------------------------------------------------------ construction (mirrors blockchain.run_pipeline)
    def _build(self):
        c = self.cfg; rng = np.random.default_rng(c["seed"])
        self.records, self.truth, self.source_desc = load_records(c["source"], c["n_patients"], c["n_steps"])
        self.scheme, self.chain, self.contracts = encryption.MockKyber(), bc.Chain(), bc.SmartContractEngine()
        self.cluster = consensus.ConsensusCluster("Raft", c["n_nodes"], seed=c["seed"])
        if c["crashed"]: self.cluster.crash(c["crashed"])
        self.cluster.compromised = set(rng.choice(np.flatnonzero(self.cluster.alive), c["compromised"], replace=False).tolist())
        self.contracts.register("critical-vitals alert", lambda tx: tx.get("alert", False))
        self.contracts.register("sensor maintenance", lambda tx: tx.get("quarantined", 0) > 0)
        self.contracts.register("access audit", lambda tx: tx.get("event") in ("allow", "deny", "policy_deny"))
        self.consensus_log, self.audit_buf, self.tampered = [], [], {}
        self.requests = []                                        # hospitals' own off-chain request records (who asked for what)
        self.n_requests = 0                                       # total ever made, even after the list is trimmed
        self.revoked_p = set()                                    # policy tokens that a patient revoked (shown as "revoked")
        self._reset_scans()
        self.built_at = time.time()
        self.ac = HashCommitmentAC(audit_sink=self.audit_buf.append)
        self.ps = PolicyStore(audit_sink=self.audit_buf.append)
        self.devices, self.label_of = {}, {}
        self.hospitals = {h: dict(requester={}, policy={}) for h in HOSPITALS}
        for label in self.records:                              # consent: every patient grants hospA a token and a read policy
            dev = PatientDevice(label); self.devices[dev.pseud] = dev; self.label_of[dev.pseud] = label
            p, s = dev.issue_token(PERMISSION); self.ac.enroll(dev.pseud, PERMISSION, p)
            self.hospitals["hospA"]["requester"][dev.pseud] = Requester("hospA", s)
            self.hospitals["hospA"]["policy"][dev.pseud] = self.ps.define(dev, "hospA", "doctor", "EHR", "read", time.time() + POLICY_TTL_S)
        self._flush_audit("consent")
        self.where = {}                                           # pseud -> [(block, position)]
        pending = []
        for pseud, dev in self.devices.items():                  # encryption at the edge + data packaging, CHUNK records per transaction
            recs = self.records[self.label_of[pseud]]
            for k in range(0, len(recs), CHUNK):
                chunk = recs[k:k + CHUNK]
                rec = dict(pid=pseud, steps=[r["step"] for r in chunk], t_s=[r["t_s"] for r in chunk],
                           hr=[r["hr"] for r in chunk], raw=[r["raw"] for r in chunk])
                hrs = np.array([np.nan if v is None else v for v in rec["hr"]], float); ok = np.isfinite(hrs)
                meta = dict(pseud=pseud, ts=time.time(), steps=f"{chunk[0]['step']}-{chunk[-1]['step']}",
                            alert=bool(np.any((hrs[ok] < CFG["ALERT_RANGE"][0]) | (hrs[ok] > CFG["ALERT_RANGE"][1]))),
                            quarantined=int((~ok).sum()))
                ct = self.scheme.encrypt(json.dumps(rec).encode()); p_b = self.ac.commit[(pseud, PERMISSION)]
                pending.append((pseud, ct, p_b, dict(meta, meta=meta, p_bytes=p_b, tag=bc.tx_tag(ct, p_b, meta))))
        for b in range(0, len(pending), TX_PER_BLOCK):
            chunk = pending[b:b + TX_PER_BLOCK]
            res = self._commit([c for _, c, _, _ in chunk], [p for _, _, p, _ in chunk], [t for _, _, _, t in chunk], "records", "sensor records")
            for j, (pseud, _, _, _) in enumerate(chunk): self.where.setdefault(pseud, []).append((res["block"], j))

    # ------------------------------------------------------------------ ledger + consensus (same logic as run_pipeline.commit)
    def _commit(self, cts, proofs, txs, kind, why):
        """Gateway-tagged transactions -> Raft rounds until a quorum commits. A compromised leader tampers with the first record and
        honest validators reject the block (threat A1). Returns the committed block index and the rounds it took."""
        rounds = []
        for _ in range(20):
            def validate(leader):
                prop = [dict(t) for t in txs]; c0 = list(cts)
                if leader in self.cluster.compromised and c0: c0[0] = b"\x00" + c0[0][1:]
                return all(t.get("tag") is None or t["tag"] == bc.tx_tag(c, t["p_bytes"], t["meta"])
                           for t, c in zip(prop, c0 + [b""] * len(prop)))
            r = self.cluster.run_round(validate=validate)
            leader = None if r["leader"] is None else int(r["leader"])
            rounds.append(dict(leader=leader, compromised_leader=leader in self.cluster.compromised, committed=bool(r["committed"]),
                               latency_ms=None if not r["committed"] else round(float(r["latency"]), 3), msgs=int(r["msgs"])))
            if r["committed"]:
                meta_tx = [{k: v for k, v in t.items() if k not in ("p_bytes", "meta")} for t in txs]
                blk = self.chain.append(cts, proofs, dict(kind=kind, term=self.cluster.term, tx=meta_tx)); self.contracts.on_commit(blk)
                entry = dict(block=blk.index, kind=kind, why=why, rounds=rounds, term=self.cluster.term)
                self._log_consensus(entry); return entry
            if leader is None:
                entry = dict(block=None, kind=kind, why=why, rounds=rounds, error="no quorum: too many crashed nodes")
                self._log_consensus(entry); return entry
        entry = dict(block=None, kind=kind, why=why, rounds=rounds, error="no commit after 20 rounds")
        self._log_consensus(entry); return entry

    # ------------------------------------------------------------------ incremental scans (stress test: O(blocks) work on every page)
    def _reset_scans(self):
        """Blocks only change after they are appended through tamper/restore; then everything is re-scanned once."""
        self._verified, self._valid = 0, True
        self._ev, self._ev_upto, self._leak = [], 0, False

    def chain_ok(self):
        """Same answer as Chain.verify(), but only new blocks are hashed (the full chain again after a tamper or restore)."""
        with self.lock:
            bl = self.chain.blocks
            for i in range(self._verified, len(bl)):
                b = bl[i]
                if b.hash != b.compute_hash() or (i and b.prev_hash != bl[i - 1].hash): self._valid = False
            self._verified = len(bl)
            return self._valid

    def _scan_audit(self):
        with self.lock:
            pids = [d.pid for d in self.devices.values()]
            for b in self.chain.blocks[self._ev_upto:]:
                dump = json.dumps(b.metadata, default=str)          # once per block, not once per block per patient
                if any(pid in dump for pid in pids): self._leak = True
                if b.metadata.get("kind") == "audit":
                    self._ev += [dict(block=b.index, event=tx.get("event"), who=tx.get("who"), t=tx.get("t")) for tx in b.metadata["tx"]]
            self._ev_upto = len(self.chain.blocks)
            return self._ev

    def _log_consensus(self, entry):
        self.consensus_log.append(entry)
        if len(self.consensus_log) > MAX_CONSENSUS_LOG: del self.consensus_log[:-MAX_CONSENSUS_LOG]

    def _flush_audit(self, why):
        if not self.audit_buf: return None
        res = self._commit([], [], [dict(**e, tag=None) for e in self.audit_buf], "audit", why)
        if res.get("block") is not None: self.audit_buf.clear()
        return res

    # ------------------------------------------------------------------ overview
    def patients(self):
        return [dict(pseud=p, label=self.label_of[p], n_records=len(self.records[self.label_of[p]]),
                     has_truth=self.truth[self.label_of[p]] is not None) for p in self.devices]

    def overview(self):
        with self.lock:
            kinds = {}
            for b in self.chain.blocks[1:]: kinds[b.metadata.get("kind")] = kinds.get(b.metadata.get("kind"), 0) + 1
            wp, names = wildppg_available()
            return dict(config=self.cfg, source_desc=self.source_desc, patients=self.patients(), hospitals=list(HOSPITALS),
                        blocks=len(self.chain.blocks) - 1, block_kinds=kinds, chain_valid=self.chain_ok(),
                        nodes=self.nodes(), wildppg=dict(available=wp, participants=names),
                        contract_events=len(self.contracts.events), audit_pending=len(self.audit_buf))

    # ------------------------------------------------------------------ patient device (Sec 4.3.2-4.3.3)
    def _dev(self, pseud):
        if pseud not in self.devices: raise KeyError(f"unknown patient {pseud}")
        return self.devices[pseud]

    def patient_view(self, pseud):
        with self.lock:
            dev = self._dev(pseud); label = self.label_of[pseud]; commit = self.ac.commit.get((pseud, PERMISSION))
            holders = [dict(hospital=h, token_valid=H(d["requester"][pseud].s) == commit)
                       for h, d in self.hospitals.items() if pseud in d["requester"]]
            pols, now, entries = [], time.time(), self.ps.pol.get(pseud, [])
            latest = {}                                           # Eq 10: per entity, the tuple with the latest t_e governs
            for e in entries: latest[e["pi"][0]] = max(latest.get(e["pi"][0], -1), e["pi"][4])
            for e in entries:
                ent, role, R, a, te = e["pi"]
                held_by = [h for h, d in self.hospitals.items() if d["policy"].get(pseud) == e["p"]]
                revoked = e["p"] in self.revoked_p
                pols.append(dict(entity=ent, role=role, resource=R, access=a, expires=te, expired=te <= now, revoked=revoked,
                                 held_by=held_by, governing=te == latest[ent] and te > now and not revoked))
            recs = self.records[label]
            return dict(pseud=pseud, label=label, token_holders=holders, policies=pols,
                        vitals=dict(step=[r["step"] for r in recs], hr=[r["hr"] for r in recs],
                                    n_raw=[len(r["raw"]) for r in recs], truth=self.truth[label]))

    def grant_token(self, pseud, hospital):
        with self.lock:
            dev = self._dev(pseud); self._hosp(hospital)
            p, s = dev.issue_token(PERMISSION); self.ac.enroll(pseud, PERMISSION, p)
            self.hospitals[hospital]["requester"][pseud] = Requester(hospital, s)
            return dict(ok=True, ledger=self._flush_audit(f"grant token to {hospital}"))

    def define_policy(self, pseud, entity, role, resource, access, ttl_s):
        with self.lock:
            dev = self._dev(pseud); self._hosp(entity)
            if access not in ("read", "write"): raise ValueError("access must be read or write")
            ttl_s = float(ttl_s)
            if not (np.isfinite(ttl_s) and ttl_s > 0): raise ValueError("validity must be a positive number of seconds")
            if len(self.ps.pol.get(pseud, [])) >= MAX_POLICIES_PER_PATIENT:
                raise ValueError(f"at most {MAX_POLICIES_PER_PATIENT} policies per patient")
            p = self.ps.define(dev, entity, role, resource, access, time.time() + ttl_s)
            self.hospitals[entity]["policy"][pseud] = p
            return dict(ok=True, ledger=self._flush_audit(f"policy for {entity}"))

    def revoke_token(self, pseud):
        with self.lock:
            dev = self._dev(pseud); p2, _ = dev.revoke(PERMISSION); self.ac.revoke(pseud, PERMISSION, p2)
            return dict(ok=True, note="New consent token issued to nobody; every hospital's old token is now invalid.",
                        ledger=self._flush_audit("token revoked"))

    def revoke_policy(self, pseud, entity, resource):
        with self.lock:
            dev = self._dev(pseud); self._hosp(entity); now = time.time()
            if not any(e["pi"][0] == entity and e["pi"][2] == resource and e["pi"][4] > now for e in self.ps.pol.get(pseud, [])):
                raise ValueError(f"nothing to revoke: no active {resource} policy for {entity}")
            self.ps.revoke(dev, entity, resource)
            for e in self.ps.pol.get(pseud, []):                  # the replaced tuples (t_e = now) are revocations, not expiries
                if e["pi"][0] == entity and e["pi"][2] == resource and e["pi"][4] <= time.time(): self.revoked_p.add(e["p"])
            return dict(ok=True, ledger=self._flush_audit(f"policy revoked for {entity}"))

    def _hosp(self, h):
        if h not in self.hospitals: raise KeyError(f"unknown hospital {h}")   # was: created any name sent (state growth)

    # ------------------------------------------------------------------ doctor / hospital request (UC5, Fig 5.4)
    def request_access(self, hospital, pseud, resource="EHR", action="read", corrupt_first=0, policy_from_ledger=False, by=None):
        cl = self.cluster
        if int(cl.alive.sum()) < cl.quorum:                       # no decision can reach the ledger: refuse before buffering audit
            self._dev(pseud); self._hosp(hospital)                # (stress test: 5,000 entries piled up, then landed in one block)
            out = dict(granted=False, hospital=hospital, patient=self.label_of[pseud], resource=resource, action=action,
                       reason=f"No quorum: only {int(cl.alive.sum())} of {cl.n} validator nodes are alive ({cl.quorum} needed), so no decision "
                              f"can be written to the ledger and nothing is released. The checks were not run.",
                       token=dict(passed=False, attempts=[], k=CFG["RETRY_K"], ms=0.0, skipped=True),
                       policy=dict(passed=False, source="not checked", matched=None, governing=None, ms=0.0, skipped=True),
                       ledger=dict(block=None, rounds=[], error="no quorum: too many crashed nodes"))
        else:
            out = self._request_access(hospital, pseud, resource, action, corrupt_first, policy_from_ledger)
        with self.lock:                                           # the hospital's internal log; never written to the ledger
            self.requests.append(dict(t=time.time(), hospital=hospital, by=by, pseud=pseud, patient=out["patient"],
                                      resource=resource, action=action, granted=out["granted"],
                                      attempts=len(out["token"]["attempts"]), token_ok=out["token"]["passed"],
                                      policy_ok=out["policy"]["passed"], ledger_copied=bool(policy_from_ledger),
                                      block=(out["ledger"] or {}).get("block")))
            self.n_requests += 1
            if len(self.requests) > MAX_REQUESTS: del self.requests[:-MAX_REQUESTS]
        return out

    def _request_access(self, hospital, pseud, resource, action, corrupt_first, policy_from_ledger):
        with self.lock:
            self._dev(pseud); self._hosp(hospital); hd = self.hospitals[hospital]
            requester = hd["requester"].get(pseud) or Requester(hospital, os.urandom(32))   # no consent: an unknown token
            commit = self.ac.commit.get((pseud, PERMISSION))
            attempts, n = [], iter(range(10 ** 6))
            def next_request():
                i = next(n); r = requester.request(pseud, PERMISSION, corrupt=i < corrupt_first)
                attempts.append(dict(attempt=i + 1, corrupted=i < corrupt_first, nonce=r["nonce"][:12] + "...",
                                     hash_matches=H(r["token"]) == commit, token_sent=r["token"].hex()[:16] + "..."))
                return r
            t0 = time.perf_counter(); d = self.ac.verify_with_retry(next_request, CFG["RETRY_K"]); t_tok = (time.perf_counter() - t0) * 1e3
            if policy_from_ledger and self.ps.pol.get(pseud):
                p_sub, pol_src = self.ps.pol[pseud][0]["p"], "copied from the ledger"
            else:
                p_sub = hd["policy"].get(pseud) or os.urandom(32)
                pol_src = "held by the hospital" if pseud in hd["policy"] else "none held (random bytes submitted)"
            match = next((e for e in self.ps.pol.get(pseud, []) if e["p"] == p_sub), None)
            star = None
            if match is not None:
                same = [e["pi"] for e in self.ps.pol[pseud] if e["pi"][0] == match["pi"][0]]
                star = max(same, key=lambda pi: pi[4])
            t0 = time.perf_counter(); pol_ok = self.ps.check(pseud, p_sub, resource, action); t_pol = (time.perf_counter() - t0) * 1e3
            ledger = self._flush_audit(f"{hospital} access decision")
            committed = ledger is not None and ledger.get("block") is not None
            granted = bool(d) and pol_ok and committed        # Sec 3.2: a decision is only acted on once it is on the ledger
            reason = None
            if not d:
                reason = (f"The token was corrupted on all {CFG['RETRY_K']} attempts (Alg. 4 gave up)." if corrupt_first >= CFG["RETRY_K"]
                          else "No valid consent token: the patient never granted this hospital a token, or revoked it.")
            elif not pol_ok:
                if match is None:
                    reason = "No matching policy: the patient has not given this hospital a policy, or revoked it."
                elif star is not None and star[4] <= time.time():
                    reason = "The patient's governing policy for this hospital has expired."
                elif star is not None:
                    reason = f"The patient's policy allows {star[3]} on {star[2]} only, not {action} on {resource}."
                else:
                    reason = "The policy check failed."
            elif not committed:
                reason = "The decision could not be committed to the ledger (" + ((ledger or {}).get("error") or "no quorum") + "), so nothing is released."
            out = dict(granted=granted, reason=reason, hospital=hospital, patient=self.label_of[pseud], resource=resource, action=action,
                       token=dict(passed=bool(d), attempts=attempts, k=CFG["RETRY_K"], ms=round(t_tok, 4)),
                       policy=dict(passed=pol_ok, source=pol_src, matched=None if match is None else _pi(match["pi"]),
                                   governing=None if star is None else _pi(star), ms=round(t_pol, 4)),
                       ledger=ledger)
            if granted and resource == "EHR" and action == "read":
                hr, steps, t_dec, bad = [], [], 0.0, []
                for bi, j in self.where.get(pseud, []):
                    ct = self.chain.blocks[bi].ciphertexts[j]; t0 = time.perf_counter()
                    try:
                        rec = json.loads(self.scheme.decrypt(ct))
                    except Exception:                             # tampered ciphertext: the AEAD tag no longer verifies
                        bad.append(bi); continue
                    finally:
                        t_dec += (time.perf_counter() - t0) * 1e3
                    hr += rec["hr"]; steps += rec["steps"]
                if bad:
                    out.update(granted=False, reason=f"Access was allowed, but the record's ciphertext in block(s) "
                               f"{', '.join('#%d' % b for b in sorted(set(bad)))} fails its integrity check (tampered ledger). Nothing is released.",
                               tampered_blocks=sorted(set(bad)))
                else:
                    out["record"] = dict(step=steps, hr=hr, truth=self.truth[self.label_of[pseud]], decrypt_ms=round(t_dec, 3),
                                         n_ciphertexts=len(self.where.get(pseud, [])))
            return out

    # ------------------------------------------------------------------ per-portal views
    def pseud_at(self, index):
        """Pseudonym of the index-th patient of the loaded dataset (patient accounts map to a position, not a fixed record)."""
        ps = list(self.devices)
        if not 0 <= int(index) < len(ps): raise KeyError(f"the loaded dataset has only {len(ps)} patients")
        return ps[int(index)]

    def token_valid(self, hospital, pseud):
        r = self.hospitals.get(hospital, {}).get("requester", {}).get(pseud)
        return r is not None and H(r.s) == self.ac.commit.get((pseud, PERMISSION))

    def patient_history(self, pseud):
        """What the ledger says about this patient. Audit events carry only the pseudonym (Sec 4.5), never the hospital."""
        with self.lock:
            self._dev(pseud)
            ev = [dict(block=e["block"], event=e["event"], t=e["t"]) for e in self._scan_audit() if e["who"] == pseud]
            return dict(pseud=pseud, events=ev[::-1][:HISTORY_PAGE], total=len(ev),
                        record_blocks=sorted({bi for bi, _ in self.where.get(pseud, [])}))

    def live_read_policy(self, hospital, pseud):
        """Does the hospital hold the patient's policy token, with the governing policy (Eq 10) an unexpired EHR read?"""
        held = self.hospitals.get(hospital, {}).get("policy", {}).get(pseud)
        e = next((x for x in self.ps.pol.get(pseud, []) if x["p"] == held), None)
        if e is None: return False
        star = max((x["pi"] for x in self.ps.pol[pseud] if x["pi"][0] == e["pi"][0]), key=lambda pi: pi[4])
        return star[2] == "EHR" and star[3] == "read" and star[4] > time.time()

    def doctor_patients(self, hospital):
        with self.lock:
            return [dict(p, token_valid=self.token_valid(hospital, p["pseud"]), policy_held=self.live_read_policy(hospital, p["pseud"]))
                    for p in self.patients()]

    def requests_by(self, username):
        with self.lock:
            return [r for r in self.requests if (r.get("by") or {}).get("username") == username][::-1][:100]

    def hospital_view(self, hospital):
        with self.lock:
            self._hosp(hospital); hd = self.hospitals[hospital]; now = time.time(); pats = []
            for p in self.patients():
                pols, mine = [], [e for e in self.ps.pol.get(p["pseud"], []) if e["pi"][0] == hospital]
                top = max((e["pi"][4] for e in mine), default=None)
                for e in mine:
                    _, role, R, a, te = e["pi"]; rv = e["p"] in self.revoked_p
                    pols.append(dict(role=role, resource=R, access=a, expires=te, expired=te <= now, revoked=rv,
                                     governing=te == top and te > now and not rv, held=hd["policy"].get(p["pseud"]) == e["p"]))
                tv = self.token_valid(hospital, p["pseud"])
                pats.append(dict(p, token_held=p["pseud"] in hd["requester"], token_valid=tv, policies=pols,
                                 readable=tv and self.live_read_policy(hospital, p["pseud"])))   # would an EHR read pass right now
            reqs = [r for r in self.requests if r["hospital"] == hospital]
            per_staff = {}
            for r in reqs:
                k = (r.get("by") or {}).get("username")
                if k: per_staff[k] = per_staff.get(k, 0) + 1
            return dict(hospital=hospital, patients=pats, requests=reqs[::-1][:LOG_PAGE], requests_shown=min(len(reqs), LOG_PAGE),
                        stats=dict(consenting=sum(p["token_valid"] for p in pats), readable=sum(p["readable"] for p in pats),
                                   patients=len(pats), requests=len(reqs), granted=sum(r["granted"] for r in reqs),
                                   denied=sum(not r["granted"] for r in reqs)),
                        per_staff=per_staff, since=self.built_at,
                        nodes=self.nodes(), chain_valid=self.chain_ok(), blocks=len(self.chain.blocks) - 1, source=self.cfg["source"])

    # ------------------------------------------------------------------ hospital admin: nodes, ledger, audit
    def nodes(self):
        cl = self.cluster
        return dict(n=cl.n, quorum=cl.quorum, alive=int(cl.alive.sum()), term=cl.term,
                    nodes=[dict(id=i, alive=bool(cl.alive[i]), compromised=i in cl.compromised) for i in range(cl.n)])

    def node_action(self, i, action):
        with self.lock:
            cl = self.cluster
            if not 0 <= i < cl.n: raise KeyError(f"no node {i}")
            if action == "crash": cl.alive[i] = False
            elif action == "recover": cl.alive[i] = True
            elif action == "compromise": cl.compromised.symmetric_difference_update({i})
            else: raise ValueError(action)
            return self.nodes()

    def ledger(self):
        with self.lock:
            out, bl = [], self.chain.blocks
            shown = sorted(set([0] + list(range(max(1, len(bl) - LEDGER_PAGE), len(bl))) + list(self.tampered)))
            for i in shown:                                       # genesis, the newest blocks, and any tampered block
                b = bl[i]
                ok = b.hash == b.compute_hash() if i in self.tampered or not self.chain_ok() else True   # untouched blocks verified once
                out.append(dict(index=b.index, kind=b.metadata.get("kind", "genesis"), term=b.metadata.get("term"),
                                n_tx=len(b.metadata.get("tx", [])), n_ct=len(b.ciphertexts), hash=b.hash[:16], prev=b.prev_hash[:16],
                                bytes=b.nbytes(), hash_ok=ok, tampered=b.index in self.tampered))
            return dict(blocks=out, total=len(bl), valid=self.chain_ok(), consensus=self.consensus_log[-15:][::-1])

    def block(self, i):
        with self.lock:
            if not 0 <= i < len(self.chain.blocks): raise KeyError(f"no block #{i}: the ledger has blocks 0-{len(self.chain.blocks) - 1}")
            b = self.chain.blocks[i]
            return dict(index=b.index, hash=b.hash, prev_hash=b.prev_hash, recomputed=b.compute_hash(), timestamp=b.timestamp,
                        metadata=json.loads(json.dumps(b.metadata, default=str)),
                        ciphertexts=[dict(bytes=len(c), head=c[:12].hex()) for c in b.ciphertexts],
                        proofs=[p.hex()[:24] + "..." for p in b.proofs])

    def tamper(self, i):
        with self.lock:
            if i <= 0 or i >= len(self.chain.blocks): raise KeyError("pick a non-genesis block")
            b = self.chain.blocks[i]
            if i not in self.tampered: self.tampered[i] = (list(b.ciphertexts), json.loads(json.dumps(b.metadata)))
            if b.ciphertexts: b.ciphertexts = [b"\x00" + b.ciphertexts[0][1:]] + b.ciphertexts[1:]
            else: b.metadata = dict(b.metadata, tx=b.metadata.get("tx", [])[:-1])
            self._reset_scans(); return self.ledger()

    def restore(self, i):
        with self.lock:
            if i in self.tampered:
                cts, meta = self.tampered.pop(i); b = self.chain.blocks[i]; b.ciphertexts, b.metadata = cts, meta
                self._reset_scans()
            return self.ledger()

    def audit(self):
        with self.lock:
            ev = self._scan_audit()
            return dict(events=ev[::-1][:200], total=len(ev), identity_on_ledger=self._leak,
                        contract_events=[dict(e) for e in self.contracts.events[::-1][:100]],
                        hospitals={h: dict(patients_with_token=len(d["requester"]), policies_held=len(d["policy"]))
                                   for h, d in self.hospitals.items()})


def _pi(pi):
    e, r, R, a, te = pi
    return dict(entity=e, role=r, resource=R, access=a, expires=te, expired=te <= time.time())


# ---------------------------------------------------------------------- lab: attacks and quick benchmarks (fresh state each run)
def attack_suite(n=100):
    """The seven attacks of the base's Sec 5.5 experiment (access_control.run), on a fresh patient. Accepted counts out of n."""
    dev = PatientDevice("patient-lab"); ac = HashCommitmentAC(audit_sink=lambda e: None)
    p, s = dev.issue_token(PERMISSION); ac.enroll(dev.pseud, PERMISSION, p); hosp = Requester("hospA", s)
    legit = sum(ac.verify(hosp.request(dev.pseud, PERMISSION)) for _ in range(n))
    captured = hosp.request(dev.pseud, PERMISSION); ac.verify(captured)
    ps = PolicyStore(audit_sink=lambda e: None); ps.define(dev, "hospA", "doctor", "EHR", "read", time.time() + 3600)
    attacks = [
        ("Forged random token", "Alg. 3", lambda: ac.verify(Requester("x", os.urandom(32)).request(dev.pseud, PERMISSION))),
        ("Exact replay of a captured request", "Sec 4.3.2 nonce", lambda: ac.verify(captured)),
        ("Captured token with fresh nonce/timestamp", "Eq. 7 vs Sec 4.3.2", lambda: ac.verify(Requester("x", captured["token"]).request(dev.pseud, PERMISSION))),
        ("Stale timestamp", "Sec 4.3.2 window", lambda: ac.verify(hosp.request(dev.pseud, PERMISSION, now=time.time() - 120))),
        ("Policy token copied from the ledger", "Eq. 9", lambda: ps.check(dev.pseud, ps.pol[dev.pseud][0]["p"], "EHR", "read")),
        ("Forged policy token", "Eqs. 8-10", lambda: ps.check(dev.pseud, os.urandom(32), "EHR", "read")),
    ]
    rows = [dict(attack=a, defence=ref, accepted=int(sum(f() for _ in range(n))), attempts=n) for a, ref, f in attacks]
    p2, _ = dev.revoke(PERMISSION); ac.revoke(dev.pseud, PERMISSION, p2)
    rows.append(dict(attack="Revoked token", defence="Sec 4.3.2 revoke", accepted=int(sum(ac.verify(hosp.request(dev.pseud, PERMISSION)) for _ in range(n))), attempts=n))
    for r in rows: r["paper_flaw"] = r["accepted"] > 0
    fp = 100 * sum(r["accepted"] for r in rows) / (n * len(rows))
    req = Requester("hospA", s).request(dev.pseud, PERMISSION)
    rbac = RBACContract(); rbac.assign("0xHospA", "doctor"); rbac.check_access("0xHospA", "patient-lab", "read")
    sens = dict(patient_id=dev.pid, entity="hospA", role="doctor", secret_s=s)
    views = [("Ledger: token commitments", {"|".join(k): v for k, v in ac.commit.items()}, sens),
             ("Ledger: policy commitments", [x["p"] for x in ps.pol[dev.pseud]], sens),
             ("Verifier: policy state (Eq. 10 needs it)", ps.pol, sens),
             ("Network / verifier: one access request", req, sens),
             ("RBAC baseline: contract event", rbac.events[:1], dict(patient_id="patient-lab", entity="0xHospA", role="doctor"))]
    leak = [dict(view=v, leaked=identity_leakage(obj, s_)) for v, obj, s_ in views]
    return dict(rows=rows, legitimate=dict(accepted=int(legit), attempts=n), fp_rate=round(fp, 2),
                fn_rate=round(100 * (1 - legit / n), 2), leakage=leak)


def bench_verify(n=500):
    dev = PatientDevice("patient-bench"); ac = HashCommitmentAC(audit_sink=lambda e: None)
    p, s = dev.issue_token(PERMISSION); ac.enroll(dev.pseud, PERMISSION, p); hosp = Requester("hospA", s)
    t_auth = []
    for _ in range(n):
        r = hosp.request(dev.pseud, PERMISSION); t0 = time.perf_counter_ns(); ac.verify(r); t_auth.append((time.perf_counter_ns() - t0) / 1e6)
    rbac = RBACContract(); rbac.assign("0xHospA", "doctor"); t_rbac = []
    for _ in range(n):
        t0 = time.perf_counter_ns(); rbac.check_access("0xHospA", "p", "read"); t_rbac.append((time.perf_counter_ns() - t0) / 1e6)
    return dict(n=n, auth=_stat(t_auth), rbac=_stat(t_rbac), series=dict(auth=t_auth[:100], rbac=t_rbac[:100]), paper_auth_ms=0.002)


def bench_crypto(n=100):
    from Crypto.Random import get_random_bytes
    out = []
    for sch in (encryption.RSAScheme(), encryption.MockKyber(768, True), encryption.MockKyber(model_sizes=False)):
        sch.decrypt(sch.encrypt(b"warm-up")); enc, dec, size = [], [], []
        for _ in range(n):
            m = get_random_bytes(96); t0 = time.perf_counter_ns(); c = sch.encrypt(m); t1 = time.perf_counter_ns()
            assert sch.decrypt(c) == m; t2 = time.perf_counter_ns()
            enc.append((t1 - t0) / 1e6); dec.append((t2 - t1) / 1e6); size.append(len(c))
        out.append(dict(scheme=sch.name, enc=_stat(enc), dec=_stat(dec), bytes=int(np.mean(size))))
    return dict(n=n, schemes=out)


def bench_consensus(proto="Raft", n=50, mode="normal", rounds=30, crashed=0):
    cl = consensus.ConsensusCluster(proto, int(n), seed=1, mode=mode)
    if crashed: cl.crash(int(crashed))
    lat, msgs, committed = [], [], 0
    for _ in range(int(rounds)):
        r = cl.run_round()
        if r["committed"]: committed += 1; lat.append(float(r["latency"])); msgs.append(int(r["msgs"]))
    tps = [CFG["BLOCK_SIZE"] / (x / 1000) for x in lat]
    return dict(proto=proto, n=int(n), mode=mode, rounds=int(rounds), crashed=int(crashed), quorum=cl.quorum, committed=committed,
                latency=_stat(lat) if lat else None, msgs=float(np.mean(msgs)) if msgs else None,
                tps=_stat(tps) if tps else None, series=lat)


def _stat(xs):
    a = np.asarray(xs, float)
    return dict(mean=round(float(a.mean()), 5), ci95=round(ci95(a), 5), median=round(float(np.median(a)), 5),
                min=round(float(a.min()), 5), max=round(float(a.max()), 5))
