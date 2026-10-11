"""3. Lightweight privacy-preserving access control (Sec. 4.3, 5.5, 6.1, 6.6, Figs 3 and 9)

* Eq 5: `s = HMAC(k_dev, patientID ‖ permission)` with a key that stays on the patient's device (Sec 4.3.3).
* Eqs 6-7 / 17, Algorithm 3: the ledger stores `p = H(s')` and the verifier accepts iff `H(s') = p`.
  RESOLVES: Eq 7 needs the submitted token in clear, yet Sec 4.3.2 requires replay resistance. A revealed token could be replayed with a fresh nonce,
  so each consent issues a hash chain of one-time tokens: the ledger holds `p = H(t₁)`; a request reveals `t₁`, the verifier checks `H(t₁) = p`
  (Eq 7 exactly) and then stores `p ← t₁`, so the next request must reveal `t₂` with `H(t₂) = t₁`. With chain length 1 this is exactly `p = H(s)`.
* Freshness (Sec 4.3.2): the nonce and timestamp are incorporated into the proof by `HMAC(token, pseudonym‖nonce‖ts)`; window and nonce-cache checks.
* Algorithm 4: retry up to k on failed verification (e.g. a corrupted transmission). Grant / revoke / audit trail as in Sec 4.3.2.
* Eqs 8-10: policy tokens `p = HMAC(k_s, π)`; the ledger keeps `H(p)` (so a ledger reader cannot replay `p`) plus the minimum metadata Eq 10 needs.
  Verification: ∃πᵢ matching the submitted token; Eq 10 (latest `t_e`) is applied only when the same entity has conflicting access levels for the resource;
  the requested resource and access level are enforced.
* Baseline: a smart-contract RBAC with a public role registry and public events.
* Metrics (Sec 5.5): verification time, false positives / false negatives under attack, and identity-leakage (plaintext identity/role fields on the ledger).

Library part: PatientDevice, Requester, HashCommitmentAC, PolicyStore, RBACContract.
Experiment part: run_checks() (correctness asserts) and run(ky_r) (Fig 3, Sec 5.5 metrics, Fig 9).
"""
import os, time, hmac, json
import numpy as np, pandas as pd, matplotlib.pyplot as plt
from Crypto.Random import get_random_bytes
from common import CFG, H, ci95, fmt, display, RESULTS

AUDIT_LOG = []                                                          # default sink; blockchain.py routes audit events onto the ledger

class PatientDevice:
    """Patient side of Sec 4.3: holds k_dev (Eq 5) and k_s (Eq 9); neither key ever leaves the device."""
    def __init__(self, pid):
        self.pid = pid; self.pseud = H(b"pseudonym|" + pid.encode()).hex()[:16]   # pseudonym used on-chain
        self._k_dev, self._ks, self.version = get_random_bytes(32), get_random_bytes(32), 0
    def secret(self, permission):                                       # Eq 5 (+ version so a re-issued s differs)
        return hmac.digest(self._k_dev, f"{self.pid}|{permission}|v{self.version}".encode(), "sha256")
    def issue_token(self, permission, length=CFG["TOKEN_CHAIN_LEN"]):
        """Token grant. Returns (commitment p for the ledger, one-time tokens for the authorised requester): p = H^L(s), tokens H^(L-1)(s) ... s."""
        c = [self.secret(permission)]
        for _ in range(length): c.append(H(c[-1]))
        return c[-1], c[-2::-1]
    def revoke(self, permission, length=CFG["TOKEN_CHAIN_LEN"]):       # token revoke: new s' -> new commitment overwrites the old one
        self.version += 1; return self.issue_token(permission, length)
    def policy_token(self, pi):                                         # Eqs 8-9: p = HMAC(k_s, <e, r, R, a, t_e>)
        return hmac.digest(self._ks, "|".join(map(str, pi)).encode(), "sha256")

class Requester:
    """Hospital node / doctor holding the one-time tokens it received on consent."""
    def __init__(self, name, tokens): self.name, self.tokens, self.i = name, list(tokens), 0
    def request(self, pseud, now=None, corrupt=False):
        tok = self.tokens[self.i]
        if corrupt: tok = bytes([tok[0] ^ 1]) + tok[1:]                 # transmission error
        nonce, ts = os.urandom(16).hex(), (now or time.time())
        return dict(pseud=pseud, token=tok, nonce=nonce, ts=ts, bind=hmac.digest(tok, f"{pseud}|{nonce}|{ts}".encode(), "sha256"))
    def access(self, ac, pseud, corrupt_first=0, k=CFG["RETRY_K"]):
        n = iter(range(10 ** 9))
        d = ac.verify_with_retry(lambda: self.request(pseud, corrupt=next(n) < corrupt_first), k)
        if d: self.i += 1                                               # token consumed on success
        return d

class HashCommitmentAC:
    """Algorithm 3 (enrolment + verification), Sec 4.3.2 (freshness, grant, revoke, audit), Algorithm 4 (bounded retry)."""
    def __init__(self, window_s=CFG["AUTH_WINDOW_S"], audit_sink=None):
        self.commit, self.seen, self.window = {}, set(), window_s
        self.audit = audit_sink or AUDIT_LOG.append
    def _log(self, ev, pseud): self.audit(dict(event=ev, who=pseud, t=time.time()))   # pseudonym only: no identity or role
    def enroll(self, pseud, p): self.commit[pseud] = p; self._log("grant", pseud)       # Alg 3 lines 1-3: store p on the ledger
    def revoke(self, pseud, p_new): self.commit[pseud] = p_new; self._log("revoke", pseud)  # overwrite p with H(s')
    def verify(self, req, now=None):
        now = now or time.time()
        fresh = abs(now - req["ts"]) <= self.window and req["nonce"] not in self.seen
        bound = hmac.compare_digest(req["bind"], hmac.digest(req["token"], f"{req['pseud']}|{req['nonce']}|{req['ts']}".encode(), "sha256"))
        ok = fresh and bound and H(req["token"]) == self.commit.get(req["pseud"])           # Eq 7: Verify(p, s') = 1 iff H(s') = p
        if ok: self.seen.add(req["nonce"]); self.commit[req["pseud"]] = req["token"]       # revealed token is consumed
        self._log("allow" if ok else "deny", req["pseud"]); return ok
    def verify_with_retry(self, next_attempt, k=CFG["RETRY_K"]):      # Algorithm 4: d = 1 on the first matching attempt, else 0 after k
        for _ in range(k):
            if self.verify(next_attempt()): return 1
        return 0

ACCESS_RANK = {"none": 0, "read": 1, "write": 2}
class PolicyStore:
    """Sec 4.3.3. Ledger state per patient: H(p) for each policy token p = HMAC(k_s, pi) plus the metadata Eq 10 needs
    (ASSUMPTION): hashed entity id, resource type R, access level a, expiry t_e. The role r stays inside the HMAC."""
    def __init__(self, audit_sink=None): self.pol, self.audit = {}, audit_sink or AUDIT_LOG.append
    def define(self, device, entity, role, resource, access, t_e):    # 1. policy definition (Eqs 8-9)
        p = device.policy_token((entity, role, resource, access, t_e))
        self.pol.setdefault(device.pseud, []).append(dict(eh=H(entity.encode()), R=resource, a=access, te=t_e, cp=H(p)))
        self.audit(dict(event="policy_define", who=device.pseud, t=time.time())); return p   # p goes to the entity, H(p) to the ledger
    def revoke(self, device, entity, resource, now=None):             # 4. revocation: replaced by pi' with an updated (expired) t_e
        now = now or time.time(); eh = H(entity.encode())
        keep = [x for x in self.pol.get(device.pseud, []) if not (x["eh"] == eh and x["R"] == resource)]
        p_new = device.policy_token((entity, "revoked", resource, "none", now))
        self.pol[device.pseud] = keep + [dict(eh=eh, R=resource, a="none", te=now, cp=H(p_new))]
        self.audit(dict(event="policy_revoke", who=device.pseud, t=now))
    def check(self, pseud, entity, p_sub, resource, access, now=None):  # 2. verification + 3. conflict resolution (Eq 10)
        now = now or time.time(); eh = H(entity.encode())
        cands = [x for x in self.pol.get(pseud, []) if x["eh"] == eh and x["R"] == resource]
        match = next((x for x in cands if hmac.compare_digest(x["cp"], H(p_sub))), None)   # exists pi_i: H(p') = H(HMAC(k_s, pi_i))
        if match is not None and len({x["a"] for x in cands}) > 1:   # conflicting access levels -> pi* = argmax t_e
            match = match if match is max(cands, key=lambda x: x["te"]) else None
        ok = match is not None and match["te"] > now and 0 < ACCESS_RANK[access] <= ACCESS_RANK[match["a"]]
        self.audit(dict(event="policy_allow" if ok else "policy_deny", who=pseud, t=now)); return ok

class RBACContract:
    """Baseline (Sec 5.5 / 6.1): smart-contract RBAC. The role registry is public contract state and every call emits a public event."""
    ROLE_PERMS = {"doctor": {"read", "write"}, "nurse": {"read"}, "auditor": {"audit"}}
    def __init__(self): self.roles, self.events = {}, []
    def assign(self, addr, role): self.roles[addr] = role
    def check_access(self, addr, patient_id, action):
        role = self.roles.get(addr); ok = action in self.ROLE_PERMS.get(role, ())
        self.events.append(dict(addr=addr, role=role, patient=patient_id, action=action, ok=ok)); return ok


def run_checks():
    """Correctness checks: replay, freshness, Algorithm 4, revocation, Eqs 8-10 policy logic, audit pseudonymity."""
    dev = PatientDevice("patient-0001"); ac = HashCommitmentAC()
    p, toks = dev.issue_token("read_ehr"); ac.enroll(dev.pseud, p); hosp = Requester("hospA", toks)
    r1 = hosp.request(dev.pseud); assert ac.verify(r1); hosp.i += 1
    assert not ac.verify(r1)                                                            # A3: exact replay
    fresh = dict(r1, nonce=os.urandom(16).hex(), ts=time.time()); assert not ac.verify(fresh)   # replay with new nonce/ts: binding fails
    fresh["bind"] = hmac.digest(r1["token"], f"{fresh['pseud']}|{fresh['nonce']}|{fresh['ts']}".encode(), "sha256")
    assert not ac.verify(fresh)                                                         # attacker re-binds a captured token: already consumed
    assert not ac.verify(hosp.request(dev.pseud, now=time.time() - 3600))               # stale timestamp
    assert hosp.access(ac, dev.pseud, corrupt_first=2) == 1                             # Algorithm 4: succeeds on attempt 3
    assert hosp.access(ac, dev.pseud, corrupt_first=3) == 0                             # Algorithm 4: gives up after k = 3
    p2, toks2 = dev.revoke("read_ehr"); ac.revoke(dev.pseud, p2)
    assert hosp.access(ac, dev.pseud) == 0 and Requester("hospA", toks2).access(ac, dev.pseud) == 1   # revoked chain dead, new chain works
    ps, t = PolicyStore(), time.time()
    p_ehr = ps.define(dev, "hospA", "doctor", "EHR", "read", t + 100)
    p_aud = ps.define(dev, "hospA", "doctor", "audit_logs", "read", t + 500)
    assert ps.check(dev.pseud, "hospA", p_ehr, "EHR", "read")                          # older but non-conflicting policy still valid
    assert not ps.check(dev.pseud, "hospA", p_ehr, "EHR", "write")                     # access level enforced
    assert not ps.check(dev.pseud, "hospA", p_ehr, "audit_logs", "read")               # resource enforced
    p_w = ps.define(dev, "hospA", "doctor", "EHR", "write", t + 300)                   # conflicting level for the same entity + resource
    assert ps.check(dev.pseud, "hospA", p_w, "EHR", "write") and not ps.check(dev.pseud, "hospA", p_ehr, "EHR", "read")   # Eq 10
    assert not ps.check(dev.pseud, "hospB", p_w, "EHR", "read")                        # stolen token used by another entity
    assert not ps.check(dev.pseud, "hospA", p_w, "EHR", "read", now=t + 400)           # expired
    ps.revoke(dev, "hospA", "EHR"); assert not ps.check(dev.pseud, "hospA", p_w, "EHR", "read")
    assert ps.check(dev.pseud, "hospA", p_aud, "audit_logs", "read")                   # other resource unaffected by the revocation
    assert not any(dev.pid in json.dumps(e, default=str) for e in AUDIT_LOG)            # audit trail never holds the patient identity
    print("Access-control checks passed: replay (exact, re-nonced, re-bound), stale timestamp, Algorithm 4 retry limit, revocation,"
          " policy resource/level enforcement, Eq 10 conflict resolution, expiry, stolen policy token, audit pseudonymity.")


def run(ky_r):
    """Fig 3 (verification time), Sec 5.5 (FP / FN / identity leakage) and Sec 6.6 / Fig 9 (proof generation vs ky_r enc/dec times)."""
    # ---------------- Fig 3: verification time; Sec 5.5: FP / FN / identity leakage ----------------
    N = CFG["AUTH_ROUNDS"]; dev = PatientDevice("patient-0002"); ac = HashCommitmentAC(audit_sink=lambda e: None)
    p, toks = dev.issue_token("read_ehr", length=N + 5); ac.enroll(dev.pseud, p); hosp = Requester("hospA", toks)
    t_auth, legit_ok = [], 0
    for _ in range(N):
        req = hosp.request(dev.pseud); t0 = time.perf_counter_ns(); ok = ac.verify(req); t_auth.append((time.perf_counter_ns() - t0) / 1e6)
        legit_ok += ok; hosp.i += ok
    rbac = RBACContract(); rbac.assign("0xHospA", "doctor"); t_rbac = []
    for _ in range(N):
        t0 = time.perf_counter_ns(); rbac.check_access("0xHospA", "patient-0002", "read"); t_rbac.append((time.perf_counter_ns() - t0) / 1e6)
    t_auth, t_rbac = np.array(t_auth), np.array(t_rbac)

    attacks = {}
    captured = hosp.request(dev.pseud); ac.verify(captured); hosp.i += 1                 # attacker records a request that was accepted
    def rebind(tok, pseud):
        nonce, ts = os.urandom(16).hex(), time.time()
        return dict(pseud=pseud, token=tok, nonce=nonce, ts=ts, bind=hmac.digest(tok, f"{pseud}|{nonce}|{ts}".encode(), "sha256"))
    attacks["forged random token"] = [ac.verify(rebind(os.urandom(32), dev.pseud)) for _ in range(N)]
    attacks["exact replay"] = [ac.verify(captured) for _ in range(N)]
    attacks["replay with fresh nonce/ts"] = [ac.verify(rebind(captured["token"], dev.pseud)) for _ in range(N)]
    attacks["field tampering"] = [ac.verify(dict(hosp.request(dev.pseud), ts=time.time() + 1)) for _ in range(N)]
    attacks["stale timestamp"] = [ac.verify(hosp.request(dev.pseud, now=time.time() - 120)) for _ in range(N)]
    p_new, toks_new = dev.revoke("read_ehr", length=5); ac.revoke(dev.pseud, p_new)
    attacks["revoked token"] = [ac.verify(hosp.request(dev.pseud)) for _ in range(N)]
    sec = pd.DataFrame({"attempts": [N] + [N] * len(attacks), "accepted": [legit_ok] + [int(sum(v)) for v in attacks.values()]},
                       index=["legitimate requests"] + [f"attack: {a}" for a in attacks])
    sec["rate_%"] = 100 * sec.accepted / sec.attempts
    fn_rate, fp_rate = 100 * (1 - legit_ok / N), 100 * sum(sum(v) for v in attacks.values()) / (N * len(attacks))
    print(f"Security metrics (Sec 5.5): false-negative rate {fn_rate:.2f}%, false-positive rate {fp_rate:.2f}%"); display(sec)
    leak = pd.DataFrame({"plaintext identity/role fields per access event": [0, 3],
                         "fields": ["pseudonym + token hash only", "address, role, patient id"]}, index=["Hash-commitment proof", "Smart-contract RBAC"])
    display(leak)
    display(pd.DataFrame({"mean_ms": [fmt(t_auth.mean(), ci95(t_auth), 5), fmt(t_rbac.mean(), ci95(t_rbac), 5)]},
                         index=["Authorization proof verification", "Smart-contract RBAC check"]))
    RESULTS.update(auth_ms=t_auth.mean(), rbac_ms=t_rbac.mean(), fp=fp_rate, fn=fn_rate)
    fig, ax = plt.subplots(figsize=(7, 3.5)); ax.plot(t_auth[:100], "b--", label="Authorization proof"); ax.plot(t_rbac[:100], "y-", label="Smart-contract RBAC")
    ax.set_xlabel("Access attempt"); ax.set_ylabel("Time (ms)"); ax.legend(); ax.grid(alpha=.3); ax.set_title("Access-control verification time (cf. Fig 3)")
    plt.savefig("fig03_access_time.png", bbox_inches="tight"); plt.show()

    # ---------------- Sec 6.6 / Fig 9: proof generation vs encryption / decryption ----------------
    t_proof = []
    for i in range(CFG["CRYPTO_ROUNDS"] * CFG["N_RUNS"]):
        t0 = time.perf_counter_ns(); s_ = dev.secret(f"perm{i}"); H(s_); t_proof.append((time.perf_counter_ns() - t0) / 1e6)   # Eq 5 + Eq 17
    t_proof = np.array(t_proof); RESULTS["proof_gen_ms"] = t_proof.mean()
    print(f"Proof generation (Eq 5 + Eq 17): {fmt(t_proof.mean(), ci95(t_proof), 5)} ms")
    fig, ax = plt.subplots(figsize=(6, 3.5))
    ax.boxplot([ky_r["enc"], ky_r["dec"], t_proof], flierprops=dict(marker="D", markerfacecolor="red"))
    ax.set_xticks([1, 2, 3], ["Encrypt (ms)", "Decrypt (ms)", "Authorization proof (ms)"])
    ax.set_ylabel("Time (ms)"); ax.set_title("Distribution of cryptographic operation times (cf. Fig 9)"); ax.grid(alpha=.3)
    plt.savefig("fig09_crypto_distribution.png", bbox_inches="tight"); plt.show()


if __name__ == "__main__":
    import encryption                                                   # Fig 9 needs the Kyber-inspired enc/dec timings
    run_checks()
    run(encryption.run()["ky_r"])
