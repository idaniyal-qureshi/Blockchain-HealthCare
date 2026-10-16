"""3. Lightweight privacy-preserving access control: paper-faithful (Sec. 4.3, 5.5, 6.1, 6.6, Table 2, Figs 3 and 9)

This file implements the access-control layer exactly as Hao et al. describe it, including its weaknesses. Nothing is fixed.
Comment tags:
* `# PAPER`           the line implements the cited equation / algorithm line / table row as written.
* `# GAP`             the paper gives no value or mechanism; the minimum needed to run is used.
* `# PAPER-CONFLICT`  the paper contradicts itself; the equations / algorithms are followed over the prose.
* `# PAPER-FLAW`      a check or experiment that shows a weakness of the design as written.

Paper elements
* Eq 5:          s = HMAC(k_dev, patientID ‖ permission), computed on the patient's device.
* Eq 6 / Eq 17:  p = H(s), H = SHA-256 (Sec 4.3, Sec 5.5, Table 2 "Proof Generation").
* Algorithm 3:   enrolment: p <- H(s), store p on the ledger.  Verification: if H(s') = p grant, else deny.
* Eq 7:          Verify(p, s') = 1 iff H(s') = p.
* Algorithm 4:   for i = 1..k: h <- H(s'); if h = p: d <- 1, break; else request retry or abort, d <- 0.  return d.
* Sec 4.3.2:     token grant / token revoke (new token, old p overwritten) / audit trail / freshness: each proof carries a
                 timestamp and a nonce; out-of-window or reused ones are rejected.
* Eqs 8-10:      policy tuple pi = <e, r, R, a, t_e>; commitment p = HMAC(k_s, pi) on-chain; the submitted proof is matched
                 against the stored commitments; for policies of the same entity the one with the latest t_e is selected (Eq 10).
                 Revocation replaces a policy with a new tuple, invalidating the earlier hash.
* Table 2:       SHA-256 commitment-based (non-interactive); 100-500 benchmark requests, average proof time; vs. smart-contract RBAC.
* Sec 5.5:       metrics: verification time, false positives, false negatives, identity leakage.

Library part: PatientDevice, Requester, HashCommitmentAC, PolicyStore, RBACContract, identity_leakage.
Experiment part: run_checks() (what the paper's design does, including the attacks it lets through) and run(ky_r) (Fig 3, Sec 5.5, Fig 9).
"""
import os, time, hmac, json
import numpy as np, pandas as pd, matplotlib.pyplot as plt
from Crypto.Random import get_random_bytes
from common import CFG, H, ci95, fmt, display, RESULTS

AUDIT_LOG = []                                                          # default audit sink; blockchain.py routes audit events onto the ledger

def _now(now): return time.time() if now is None else now

class PatientDevice:
    """Patient side of Sec 4.3. Holds k_dev (Eq 5) and k_s (Eq 9), generated locally (Sec 4.3.3)."""
    def __init__(self, pid):
        self.pid = pid
        self.pseud = H(b"pseudonym|" + pid.encode()).hex()[:16]       # GAP: the ledger needs an index for p that is not the identity
        self._k_dev, self._ks = get_random_bytes(32), get_random_bytes(32)   # GAP: key sizes not given (256-bit used)
    def secret(self, permission):
        return hmac.digest(self._k_dev, (self.pid + permission).encode(), "sha256")   # PAPER Eq 5: s = HMAC(k_dev, patientID ‖ permission)
    def issue_token(self, permission):
        """Token grant (Sec 4.3.2). Returns (p for the ledger, s for the authorised requester)."""
        s = self.secret(permission)
        return H(s), s                                                  # PAPER Eq 6 / Eq 17 / Alg 3 line 2: p <- H(s)
        # GAP: how s reaches the hospital is not specified
    def revoke(self, permission):
        """Token revoke (Sec 4.3.2): a new token is issued and the old p is overwritten.
        GAP: Eq 5 is deterministic, so a new s needs a new key; Sec 4.3.3 says keys are rotated on policy updates -> rotate k_dev."""
        self._k_dev = get_random_bytes(32)
        return self.issue_token(permission)
    def policy_token(self, pi):
        return hmac.digest(self._ks, "|".join(map(str, pi)).encode(), "sha256")   # PAPER Eq 9: p = HMAC(k_s, pi)

class Requester:
    """Hospital node holding the token s it was given at consent."""
    def __init__(self, name, s): self.name, self.s = name, s
    def request(self, pseud, permission, now=None, corrupt=False):
        """Access request. PAPER Eq 7 / Alg 4 input: the submitted token s' itself is sent (PAPER-CONFLICT: Alg 4's prose says
        'no secret is transmitted', but H(s') can only be computed from s'). Sec 4.3.2: the proof carries a timestamp and a nonce;
        GAP: the paper gives no construction tying them to s', so they are plain fields."""
        tok = bytes([self.s[0] ^ 1]) + self.s[1:] if corrupt else self.s   # simulated transmission error (for Alg 4's retry)
        return dict(pseud=pseud, permission=permission, token=tok, nonce=os.urandom(16).hex(), ts=_now(now))
    def access(self, ac, pseud, permission, corrupt_first=0, k=CFG["RETRY_K"]):
        n = iter(range(10 ** 9))
        return ac.verify_with_retry(lambda: self.request(pseud, permission, corrupt=next(n) < corrupt_first), k)

class HashCommitmentAC:
    """Algorithm 3 (enrolment + verification), Algorithm 4 (bounded retry), Sec 4.3.2 (grant, revoke, audit, freshness)."""
    def __init__(self, window_s=CFG["AUTH_WINDOW_S"], audit_sink=None):  # GAP: the acceptable timestamp window is not given
        self.commit, self.seen, self.window = {}, set(), window_s     # commit: (pseudonym, permission) -> p  (the on-ledger state)
        self.audit = audit_sink or AUDIT_LOG.append
    def _log(self, ev, pseud): self.audit(dict(event=ev, who=pseud, t=time.time()))   # Sec 4.3.2 / 4.5: audit event, no identity
    def enroll(self, pseud, permission, p):                            # PAPER Alg 3 lines 1-3: store p on the blockchain ledger
        self.commit[(pseud, permission)] = p; self._log("grant", pseud)
    def revoke(self, pseud, permission, p_new):                        # PAPER Sec 4.3.2: old p overwritten by the new commitment
        self.commit[(pseud, permission)] = p_new; self._log("revoke", pseud)
    def fresh(self, req, now=None):
        """PAPER Sec 4.3.2: reject a timestamp outside the window or a nonce seen before."""
        ok = abs(_now(now) - req["ts"]) <= self.window and req["nonce"] not in self.seen
        self.seen.add(req["nonce"]); return ok
    def verify(self, req, now=None):
        """PAPER Alg 3 lines 4-8 / Eq 7: grant iff H(s') = p (after the Sec 4.3.2 freshness check). p is NOT changed afterwards."""
        p = self.commit.get((req["pseud"], req["permission"]))
        ok = self.fresh(req, now) and H(req["token"]) == p           # PAPER Alg 3 line 5: if H(s') = p
        self._log("allow" if ok else "deny", req["pseud"]); return ok
    def verify_with_retry(self, next_request, k=CFG["RETRY_K"]):      # GAP: Alg 4 takes k as input but gives no value (k = 3)
        """PAPER Algorithm 4. A failed attempt triggers 'request retry' (line 7), i.e. a new submission."""
        d = 0
        for i in range(1, k + 1):                                       # line 1: for i <- 1 to k
            if self.verify(next_request()):                             # lines 2-3: h <- H(s'); if h = p
                d = 1; break                                            # lines 4-5
            d = 0                                                       # lines 6-8: request retry or abort; d <- 0
        return d                                                        # line 9

class PolicyStore:
    """Sec 4.3.3, Eqs 8-10. Ledger state: the commitment p of each policy.
    PAPER-CONFLICT: Eq 10 selects the policy with the latest t_e among those of the same entity, so the verifier must read e and t_e
    of every tuple; the prose says roles and identities are not disclosed. Equations win: the verifier keeps the tuples pi."""
    def __init__(self, audit_sink=None): self.pol, self.audit = {}, audit_sink or AUDIT_LOG.append
    def define(self, device, entity, role, resource, access, t_e):
        pi = (entity, role, resource, access, t_e)                     # PAPER Eq 8: pi = <e, r, R, a, t_e>
        p = device.policy_token(pi)                                     # PAPER Eq 9
        self.pol.setdefault(device.pseud, []).append(dict(pi=pi, p=p))  # PAPER: commitment p on-chain (pi: see class docstring)
        self.audit(dict(event="policy_define", who=device.pseud, t=time.time())); return p   # p is handed to the entity
    def revoke(self, device, entity, resource, now=None):
        """PAPER Sec 4.3.3: the policy is replaced by a new tuple pi' with an updated t_e, invalidating the earlier hash."""
        now = _now(now); lst = self.pol.get(device.pseud, [])
        for i, x in enumerate(lst):
            e, r, R, a, _ = x["pi"]
            if e == entity and R == resource:
                pi_new = (e, r, R, a, now); lst[i] = dict(pi=pi_new, p=device.policy_token(pi_new))
        self.audit(dict(event="policy_revoke", who=device.pseud, t=now))
    def check(self, pseud, p_sub, resource, access, now=None):
        """PAPER Sec 4.3.3: match the submitted proof against the stored commitments; Eq 10: among the policies of the matched
        entity take pi* = argmax t_e; grant if pi* covers the request.
        GAP: the paper does not say who the requester is, so nothing checks that the submitter is the entity e."""
        now = _now(now); lst = self.pol.get(pseud, [])
        match = next((x for x in lst if x["p"] == p_sub), None)         # PAPER: submitted proof matches a stored commitment
        ok = False
        if match is not None:
            e = match["pi"][0]
            pi_star = max((x["pi"] for x in lst if x["pi"][0] == e), key=lambda pi: pi[4])   # PAPER Eq 10: argmax t_e, same entity
            _, _, R, a, t_e = pi_star
            ok = R == resource and a == access and t_e > now            # GAP: matching rule not defined -> exact R and a, not expired
        self.audit(dict(event="policy_allow" if ok else "policy_deny", who=pseud, t=now)); return ok

class RBACContract:
    """Baseline (Sec 5.5 / 6.1 / Table 2): smart-contract RBAC. GAP: the paper gives no details; a public role registry with a
    public event per call is used."""
    ROLE_PERMS = {"doctor": {"read", "write"}, "nurse": {"read"}, "auditor": {"audit"}}
    def __init__(self): self.roles, self.events = {}, []
    def assign(self, addr, role): self.roles[addr] = role
    def check_access(self, addr, patient_id, action):
        role = self.roles.get(addr); ok = action in self.ROLE_PERMS.get(role, ())
        self.events.append(dict(addr=addr, role=role, patient=patient_id, action=action, ok=ok)); return ok

def identity_leakage(view, sensitive):
    """Sec 5.5 identity-leakage metric (GAP: not defined in the paper): which sensitive values appear in plaintext in `view`."""
    text = json.dumps(view, default=lambda o: o.hex() if isinstance(o, bytes) else str(o))
    return [k for k, v in sensitive.items() if (v.hex() if isinstance(v, bytes) else str(v)) in text]


def run_checks():
    """What the paper's design does. Every row is asserted; 'paper' is the behaviour the design as written must show."""
    rows = []
    def check(scenario, ref, observed, expected, labels=("ACCEPTED", "rejected")):
        assert observed == expected, f"{scenario}: got {observed}, the paper's design gives {expected}"
        rows.append(dict(scenario=scenario, paper_ref=ref, result=labels[0] if observed else labels[1],
                         note="PAPER-FLAW" if (observed and "attack" in scenario) else ""))

    dev = PatientDevice("patient-0001"); ac = HashCommitmentAC()
    p, s = dev.issue_token("read_ehr"); ac.enroll(dev.pseud, "read_ehr", p); hosp = Requester("hospA", s)
    check("legitimate request", "Alg 3 / Eq 7", ac.verify(hosp.request(dev.pseud, "read_ehr")), True)
    check("same s used again (new request)", "Alg 3: p is static", ac.verify(hosp.request(dev.pseud, "read_ehr")), True)
    check("wrong token", "Alg 3 line 8", ac.verify(Requester("x", os.urandom(32)).request(dev.pseud, "read_ehr")), False)
    check("token for another permission", "Eq 5", ac.verify(hosp.request(dev.pseud, "write_ehr")), False)
    r1 = hosp.request(dev.pseud, "read_ehr"); ac.verify(r1)
    check("attack: exact replay (same nonce)", "Sec 4.3.2", ac.verify(r1), False)
    check("attack: stale timestamp (1 h old)", "Sec 4.3.2", ac.verify(hosp.request(dev.pseud, "read_ehr", now=time.time() - 3600)), False)
    eaves = Requester("eavesdropper", r1["token"])                     # s' was sent in the clear, so an observer has s
    check("attack: captured s' replayed with fresh nonce/ts", "Sec 4.3.2 vs Eq 7", ac.verify(eaves.request(dev.pseud, "read_ehr")), True)
    check("Alg 4: 2 corrupted attempts, 3rd clean", "Alg 4", hosp.access(ac, dev.pseud, "read_ehr", corrupt_first=2), 1)
    check("Alg 4: k corrupted attempts", "Alg 4", hosp.access(ac, dev.pseud, "read_ehr", corrupt_first=3), 0)
    p2, s2 = dev.revoke("read_ehr"); ac.revoke(dev.pseud, "read_ehr", p2)
    check("old s after token revoke", "Sec 4.3.2", ac.verify(hosp.request(dev.pseud, "read_ehr")), False)
    check("new s after token revoke", "Sec 4.3.2", ac.verify(Requester("hospA", s2).request(dev.pseud, "read_ehr")), True)

    ps, t = PolicyStore(), time.time()
    p_ehr = ps.define(dev, "hospA", "doctor", "EHR", "read", t + 100)
    check("policy: matching request", "Eqs 8-10", ps.check(dev.pseud, p_ehr, "EHR", "read"), True)
    check("policy: other access level", "Eq 8 (a)", ps.check(dev.pseud, p_ehr, "EHR", "write"), False)
    check("policy: other resource", "Eq 8 (R)", ps.check(dev.pseud, p_ehr, "audit_logs", "read"), False)
    check("policy: after expiry", "Eq 8 (t_e)", ps.check(dev.pseud, p_ehr, "EHR", "read", now=t + 200), False)
    check("attack: other entity uses hospA's p", "Sec 4.3.3 (no requester check)", ps.check(dev.pseud, p_ehr, "EHR", "read"), True)
    ledger_copy = ps.pol[dev.pseud][0]["p"]                            # p is stored on-chain, readable by any ledger reader
    check("attack: ledger reader submits stored p", "Eq 9 (p on-chain)", ps.check(dev.pseud, ledger_copy, "EHR", "read"), True)
    ps.define(dev, "hospA", "doctor", "audit_logs", "read", t + 500)   # second, later policy for the same entity
    check("Eq 10: older EHR policy once a later one exists", "Eq 10 (argmax t_e)", ps.check(dev.pseud, p_ehr, "EHR", "read"), False)
    ps2 = PolicyStore(); p_a = ps2.define(dev, "hospA", "doctor", "EHR", "read", t + 100)
    ps2.revoke(dev, "hospA", "EHR")
    check("policy: after revocation", "Sec 4.3.3", ps2.check(dev.pseud, p_a, "EHR", "read"), False)
    check("audit trail holds no patient identity", "Sec 4.5", not any(dev.pid in json.dumps(e, default=str) for e in AUDIT_LOG), True, ("true", "false"))
    print("Paper-faithful access-control behaviour (all rows asserted):"); display(pd.DataFrame(rows).set_index("scenario"))


def run(ky_r):
    """Fig 3 (verification time vs RBAC), Sec 5.5 (FP / FN / identity leakage), Sec 6.6 / Fig 9 (proof generation vs ky_r times)."""
    # ---------------- Fig 3 / Sec 6.1 / Table 2: verification time over 100-500 requests ----------------
    N = CFG["AUTH_ROUNDS"]; dev = PatientDevice("patient-0002"); ac = HashCommitmentAC(audit_sink=lambda e: None)
    p, s = dev.issue_token("read_ehr"); ac.enroll(dev.pseud, "read_ehr", p); hosp = Requester("hospA", s)
    t_auth, legit_ok = [], 0
    for _ in range(N):
        req = hosp.request(dev.pseud, "read_ehr"); t0 = time.perf_counter_ns(); ok = ac.verify(req); t_auth.append((time.perf_counter_ns() - t0) / 1e6)
        legit_ok += ok
    rbac = RBACContract(); rbac.assign("0xHospA", "doctor"); t_rbac = []
    for _ in range(N):
        t0 = time.perf_counter_ns(); rbac.check_access("0xHospA", "patient-0002", "read"); t_rbac.append((time.perf_counter_ns() - t0) / 1e6)
    t_auth, t_rbac = np.array(t_auth), np.array(t_rbac)

    # ---------------- Sec 5.5: false positives / false negatives under attack ----------------
    captured = hosp.request(dev.pseud, "read_ehr"); ac.verify(captured)   # an observer records one accepted request
    ps = PolicyStore(audit_sink=lambda e: None); t = time.time()
    ps.define(dev, "hospA", "doctor", "EHR", "read", t + 3600)
    attacks = {
        "forged random token": lambda: ac.verify(Requester("x", os.urandom(32)).request(dev.pseud, "read_ehr")),
        "exact replay": lambda: ac.verify(captured),
        "captured s' with fresh nonce/ts": lambda: ac.verify(Requester("x", captured["token"]).request(dev.pseud, "read_ehr")),
        "stale timestamp": lambda: ac.verify(hosp.request(dev.pseud, "read_ehr", now=time.time() - 120)),
        "policy p copied from the ledger": lambda: ps.check(dev.pseud, ps.pol[dev.pseud][0]["p"], "EHR", "read"),
        "forged policy token": lambda: ps.check(dev.pseud, os.urandom(32), "EHR", "read"),
    }
    res = {a: [f() for _ in range(N)] for a, f in attacks.items()}
    p_new, s_new = dev.revoke("read_ehr"); ac.revoke(dev.pseud, "read_ehr", p_new)
    res["revoked token"] = [ac.verify(hosp.request(dev.pseud, "read_ehr")) for _ in range(N)]
    sec = pd.DataFrame({"attempts": [N] * (1 + len(res)), "accepted": [legit_ok] + [int(sum(v)) for v in res.values()]},
                       index=["legitimate requests"] + [f"attack: {a}" for a in res])
    sec["rate_%"] = 100 * sec.accepted / sec.attempts
    fn_rate, fp_rate = 100 * (1 - legit_ok / N), 100 * sum(sum(v) for v in res.values()) / (N * len(res))
    print(f"Security metrics (Sec 5.5): false-negative rate {fn_rate:.2f}%, false-positive rate {fp_rate:.2f}%"); display(sec)

    # ---------------- Sec 5.5: identity leakage, measured on what each party can see ----------------
    sensitive = dict(patient_id=dev.pid, entity="hospA", role="doctor", secret_s=s_new)
    req = Requester("hospA", s_new).request(dev.pseud, "read_ehr")
    views = {"ledger: token commitments": {"|".join(k): v for k, v in ac.commit.items()},"ledger: policy commitments": [x["p"] for x in ps.pol[dev.pseud]],
             "verifier: policy state (needed for Eq 10)": ps.pol, "network / verifier: access request": req,
             "RBAC baseline: contract events": rbac.events[:1]}
    rbac_sens = dict(patient_id="patient-0002", entity="0xHospA", role="doctor")
    leak = pd.DataFrame({"plaintext sensitive fields": [", ".join(identity_leakage(v, rbac_sens if "RBAC" in k else sensitive)) or "none"
                                                        for k, v in views.items()]}, index=list(views))
    print("Identity leakage (Sec 5.5): sensitive values visible in plaintext to each party"); display(leak)
    display(pd.DataFrame({"mean_ms": [fmt(t_auth.mean(), ci95(t_auth), 5), fmt(t_rbac.mean(), ci95(t_rbac), 5)]},
                         index=["Authorization proof verification", "Smart-contract RBAC check"]))
    RESULTS.update(auth_ms=t_auth.mean(), rbac_ms=t_rbac.mean(), fp=fp_rate, fn=fn_rate)
    fig, ax = plt.subplots(figsize=(7, 3.5)); ax.plot(t_auth[:100], "b--", label="Authorization proof"); ax.plot(t_rbac[:100], "y-", label="Smart-contract RBAC")
    ax.set_xlabel("Access attempt"); ax.set_ylabel("Time (ms)"); ax.legend(); ax.grid(alpha=.3); ax.set_title("Access-control verification time (cf. Fig 3)")
    plt.savefig("fig03_access_time.png", bbox_inches="tight"); plt.show()

    # ---------------- Sec 6.6 / Fig 9 / Table 2 "Proof Generation": s (Eq 5) and p = H(s) (Eq 17) ----------------
    t_proof = []
    for i in range(CFG["CRYPTO_ROUNDS"] * CFG["N_RUNS"]):
        t0 = time.perf_counter_ns(); H(dev.secret(f"perm{i}")); t_proof.append((time.perf_counter_ns() - t0) / 1e6)
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
