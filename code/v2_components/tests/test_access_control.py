"""Unit tests for access_control.py  (Hao et al. 2025: Sec 4.3, Eqs 5-10 and 17, Algorithms 3-4, Table 2, Sec 5.5)

access_control.py implements the paper's scheme exactly as written, including its weaknesses. These tests pin that behaviour:
  * paper elements  - each test names the equation / algorithm line / section it checks
  * PAPER-FLAW      - security requirements the paper's design does NOT meet, written as the correct property (the attack
                      must be rejected) and marked xfail(strict=True). They show as expected failures in CI. If one
                      starts passing, CI fails: the base layer no longer matches the paper (fixes belong in a separate
                      module, which reuses the same tests without the mark)
  * GAP choices     - values the paper does not give (k = 3, 30 s window, key rotation on revoke) are tested as implemented

Run from the folder that holds access_control.py:
    pytest tests/test_access_control.py -v
"""
import hmac
import json
import os

import matplotlib
matplotlib.use("Agg")
import numpy as np
import pytest

import access_control as AC
from common import CFG, H, RESULTS

PID, PERM = "patient-0001", "read_ehr"
T0 = 1_000_000.0                                    # fixed clock for freshness tests (no dependence on wall time)


@pytest.fixture
def events():
    return []


@pytest.fixture
def setup(events):
    """Enrolled consent: patient device, verifier with a private audit sink, and the hospital holding s."""
    dev = AC.PatientDevice(PID)
    ac = AC.HashCommitmentAC(audit_sink=events.append)
    p, s = dev.issue_token(PERM)
    ac.enroll(dev.pseud, PERM, p)
    return dev, ac, AC.Requester("hospA", s), p, s


def req_at(requester, dev, t, permission=PERM, **kw):
    return requester.request(dev.pseud, permission, now=t, **kw)


# ---------------------------------------------------------------- patient device: Eq 5, Eq 6/17, Eq 9
class TestPatientDevice:
    def test_pseudonym_is_stable_hex_and_hides_the_id(self):
        a, b = AC.PatientDevice(PID), AC.PatientDevice(PID)
        assert a.pseud == b.pseud and len(a.pseud) == 16
        int(a.pseud, 16)                              # valid hex
        assert PID not in a.pseud and a.pseud != AC.PatientDevice("patient-0002").pseud

    def test_eq5_secret_is_hmac_of_id_and_permission(self):
        dev = AC.PatientDevice(PID)
        expected = hmac.digest(dev._k_dev, (PID + PERM).encode(), "sha256")
        assert dev.secret(PERM) == expected and len(expected) == 32
        assert dev.secret(PERM) == dev.secret(PERM)   # deterministic for one key
        assert dev.secret(PERM) != dev.secret("write_ehr")

    def test_secret_depends_on_the_device_key(self):
        assert AC.PatientDevice(PID).secret(PERM) != AC.PatientDevice(PID).secret(PERM)

    def test_eq6_eq17_issue_token_returns_commitment_and_secret(self):
        dev = AC.PatientDevice(PID)
        p, s = dev.issue_token(PERM)
        assert s == dev.secret(PERM) and p == H(s)

    def test_revoke_rotates_the_key_and_issues_a_new_token(self):
        dev = AC.PatientDevice(PID)
        p_old, s_old = dev.issue_token(PERM)
        p_new, s_new = dev.revoke(PERM)
        assert s_new != s_old and p_new != p_old and p_new == H(s_new)

    def test_eq9_policy_token_is_hmac_of_the_tuple(self):
        dev = AC.PatientDevice(PID)
        pi = ("hospA", "doctor", "EHR", "read", 123.0)
        assert dev.policy_token(pi) == hmac.digest(dev._ks, "hospA|doctor|EHR|read|123.0".encode(), "sha256")
        assert dev.policy_token(pi) != dev.policy_token(("hospA", "doctor", "EHR", "write", 123.0))


# ---------------------------------------------------------------- requester: what is sent (Eq 7 input, Sec 4.3.2 fields)
class TestRequester:
    def test_request_carries_the_secret_in_clear_with_nonce_and_timestamp(self, setup):
        dev, _, hosp, _, s = setup
        r = req_at(hosp, dev, T0)
        assert r["token"] == s                        # PAPER-CONFLICT: Eq 7 needs s' itself
        assert r["pseud"] == dev.pseud and r["permission"] == PERM and r["ts"] == T0
        assert len(r["nonce"]) == 32
        int(r["nonce"], 16)

    def test_every_request_has_a_new_nonce(self, setup):
        dev, _, hosp, _, _ = setup
        assert len({req_at(hosp, dev, T0)["nonce"] for _ in range(50)}) == 50

    def test_corrupt_flips_one_bit_of_the_first_byte(self, setup):
        dev, _, hosp, _, s = setup
        tok = req_at(hosp, dev, T0, corrupt=True)["token"]
        assert tok[0] == s[0] ^ 1 and tok[1:] == s[1:]


# ---------------------------------------------------------------- verifier: Algorithm 3 / Eq 7
class TestAlgorithm3:
    def test_enrolment_stores_p_and_logs_a_grant(self, setup, events):
        dev, ac, _, p, _ = setup
        assert ac.commit[(dev.pseud, PERM)] == p
        assert events[-1]["event"] == "grant" and events[-1]["who"] == dev.pseud

    def test_valid_token_is_accepted(self, setup):
        dev, ac, hosp, _, _ = setup
        assert ac.verify(req_at(hosp, dev, T0), now=T0)

    def test_commitment_is_static_and_s_is_reusable(self, setup):
        dev, ac, hosp, p, _ = setup
        for i in range(5):
            assert ac.verify(req_at(hosp, dev, T0 + i), now=T0 + i)
        assert ac.commit[(dev.pseud, PERM)] == p      # p never changes after a successful check

    def test_wrong_token_is_denied(self, setup):
        dev, ac, _, _, _ = setup
        assert not ac.verify(req_at(AC.Requester("x", os.urandom(32)), dev, T0), now=T0)

    def test_token_for_another_permission_is_denied(self, setup):
        dev, ac, hosp, _, _ = setup
        assert not ac.verify(req_at(hosp, dev, T0, permission="write_ehr"), now=T0)

    def test_unknown_patient_is_denied(self, setup):
        _, ac, hosp, _, _ = setup
        assert not ac.verify(hosp.request("0" * 16, PERM, now=T0), now=T0)

    def test_decisions_are_audited_by_pseudonym_only(self, setup, events):
        dev, ac, hosp, _, _ = setup
        ac.verify(req_at(hosp, dev, T0), now=T0)
        ac.verify(req_at(AC.Requester("x", os.urandom(32)), dev, T0), now=T0)
        assert [e["event"] for e in events[-2:]] == ["allow", "deny"]
        assert all(e["who"] == dev.pseud for e in events)
        assert not any(PID in json.dumps(e) for e in events)


# ---------------------------------------------------------------- freshness: Sec 4.3.2 (window is a GAP: 30 s)
class TestFreshness:
    def test_default_window_is_the_configured_value(self):
        assert AC.HashCommitmentAC().window == CFG["AUTH_WINDOW_S"] == 30.0

    @pytest.mark.parametrize("age, ok", [(0, True), (30, True), (30.001, False), (-30, True), (-31, False), (3600, False)])
    def test_timestamp_window_boundaries(self, setup, age, ok):
        dev, ac, hosp, _, _ = setup
        assert ac.verify(req_at(hosp, dev, T0 - age), now=T0) is ok

    def test_custom_window(self, events):
        dev = AC.PatientDevice(PID)
        ac = AC.HashCommitmentAC(window_s=5, audit_sink=events.append)
        p, s = dev.issue_token(PERM)
        ac.enroll(dev.pseud, PERM, p)
        hosp = AC.Requester("hospA", s)
        assert ac.verify(req_at(hosp, dev, T0 - 5), now=T0)
        assert not ac.verify(req_at(hosp, dev, T0 - 6), now=T0)

    def test_exact_replay_is_rejected(self, setup):
        dev, ac, hosp, _, _ = setup
        r = req_at(hosp, dev, T0)
        assert ac.verify(r, now=T0)
        assert not ac.verify(r, now=T0)

    def test_nonce_of_a_rejected_request_cannot_be_reused(self, setup):
        dev, ac, hosp, _, s = setup
        bad = dict(req_at(hosp, dev, T0), token=os.urandom(32))
        assert not ac.verify(bad, now=T0)
        assert not ac.verify(dict(bad, token=s), now=T0)      # same nonce, now with the right token

    @pytest.mark.xfail(strict=True, reason="PAPER-FLAW: s' is sent in clear and the nonce/timestamp are not bound to it "
                                           "(Eq 7 vs Sec 4.3.2), so a captured token is replayable; to be fixed in the ZK module")
    def test_captured_token_with_fresh_nonce_is_rejected(self, setup):
        """Security requirement: an observer who captured one request must not be able to replay its token."""
        dev, ac, hosp, _, _ = setup
        captured = req_at(hosp, dev, T0)
        assert ac.verify(captured, now=T0)
        eavesdropper = AC.Requester("eavesdropper", captured["token"])
        assert not any(ac.verify(req_at(eavesdropper, dev, T0 + i), now=T0 + i) for i in range(10))


# ---------------------------------------------------------------- token revocation: Sec 4.3.2
class TestTokenRevocation:
    def test_old_token_rejected_new_token_accepted(self, setup, events):
        dev, ac, hosp, p_old, _ = setup
        p_new, s_new = dev.revoke(PERM)
        ac.revoke(dev.pseud, PERM, p_new)
        assert ac.commit[(dev.pseud, PERM)] == p_new != p_old
        assert events[-1]["event"] == "revoke"
        assert not ac.verify(req_at(hosp, dev, T0), now=T0)
        assert ac.verify(req_at(AC.Requester("hospA", s_new), dev, T0), now=T0)


# ---------------------------------------------------------------- Algorithm 4: bounded retry (k is a GAP: 3)
class TestAlgorithm4:
    @staticmethod
    def counting(requester, dev, corrupt_first):
        calls = []
        def nxt():
            calls.append(1)
            return requester.request(dev.pseud, PERM, corrupt=len(calls) <= corrupt_first)
        return nxt, calls

    def test_default_k_is_three(self):
        assert CFG["RETRY_K"] == 3

    @pytest.mark.parametrize("corrupt_first, d, attempts", [(0, 1, 1), (1, 1, 2), (2, 1, 3), (3, 0, 3), (10, 0, 3)])
    def test_d_and_number_of_attempts(self, setup, corrupt_first, d, attempts):
        dev, ac, hosp, _, _ = setup
        nxt, calls = self.counting(hosp, dev, corrupt_first)
        assert ac.verify_with_retry(nxt) == d
        assert len(calls) == attempts                 # stops at the first success, never more than k tries

    @pytest.mark.parametrize("k", [1, 5])
    def test_custom_k(self, setup, k):
        dev, ac, hosp, _, _ = setup
        nxt, calls = self.counting(hosp, dev, corrupt_first=k - 1)
        assert ac.verify_with_retry(nxt, k=k) == 1 and len(calls) == k
        nxt, calls = self.counting(hosp, dev, corrupt_first=k)
        assert ac.verify_with_retry(nxt, k=k) == 0 and len(calls) == k

    def test_requester_access_wrapper(self, setup):
        dev, ac, hosp, _, _ = setup
        assert hosp.access(ac, dev.pseud, PERM, corrupt_first=2) == 1
        assert hosp.access(ac, dev.pseud, PERM, corrupt_first=3) == 0


# ---------------------------------------------------------------- policies: Eqs 8-10, Sec 4.3.3
@pytest.fixture
def policy(events):
    dev = AC.PatientDevice(PID)
    ps = AC.PolicyStore(audit_sink=events.append)
    p_ehr = ps.define(dev, "hospA", "doctor", "EHR", "read", T0 + 100)
    return dev, ps, p_ehr


class TestPolicies:
    def test_eq8_eq9_define_stores_tuple_and_commitment(self, policy, events):
        dev, ps, p_ehr = policy
        entry = ps.pol[dev.pseud][0]
        assert entry["pi"] == ("hospA", "doctor", "EHR", "read", T0 + 100)
        assert entry["p"] == p_ehr == dev.policy_token(entry["pi"])
        assert events[-1]["event"] == "policy_define"

    def test_matching_request_is_allowed(self, policy):
        dev, ps, p_ehr = policy
        assert ps.check(dev.pseud, p_ehr, "EHR", "read", now=T0)

    @pytest.mark.parametrize("resource, access", [("EHR", "write"), ("audit_logs", "read"), ("EHR", "none")])
    def test_resource_and_access_level_must_match_exactly(self, policy, resource, access):
        dev, ps, p_ehr = policy
        assert not ps.check(dev.pseud, p_ehr, resource, access, now=T0)

    @pytest.mark.parametrize("now, ok", [(T0 + 99.999, True), (T0 + 100, False), (T0 + 200, False)])
    def test_expiry_is_strict(self, policy, now, ok):
        dev, ps, p_ehr = policy
        assert ps.check(dev.pseud, p_ehr, "EHR", "read", now=now) is ok

    def test_forged_token_and_unknown_patient_are_denied(self, policy):
        dev, ps, p_ehr = policy
        assert not ps.check(dev.pseud, os.urandom(32), "EHR", "read", now=T0)
        assert not ps.check("0" * 16, p_ehr, "EHR", "read", now=T0)

    def test_decisions_are_audited(self, policy, events):
        dev, ps, p_ehr = policy
        ps.check(dev.pseud, p_ehr, "EHR", "read", now=T0)
        ps.check(dev.pseud, p_ehr, "EHR", "write", now=T0)
        assert [e["event"] for e in events[-2:]] == ["policy_allow", "policy_deny"]
        assert not any(PID in json.dumps(e) for e in events)

    @pytest.mark.xfail(strict=True, reason="PAPER-FLAW: Eq 9 stores the policy token p itself on-chain and nothing checks "
                                           "who submits it, so any ledger reader can use it; to be fixed in the ZK module")
    def test_commitment_copied_from_the_ledger_is_rejected(self, policy):
        """Security requirement: reading the public ledger must not give anyone a usable policy token."""
        dev, ps, _ = policy
        ledger_copy = ps.pol[dev.pseud][0]["p"]
        assert not ps.check(dev.pseud, ledger_copy, "EHR", "read", now=T0)

    def test_eq10_latest_policy_of_the_same_entity_governs(self, policy):
        dev, ps, p_ehr = policy
        ps.define(dev, "hospA", "doctor", "audit_logs", "read", T0 + 500)
        assert not ps.check(dev.pseud, p_ehr, "EHR", "read", now=T0)        # older EHR policy no longer governs
        assert ps.check(dev.pseud, p_ehr, "audit_logs", "read", now=T0)     # the matched entity's latest policy does

    def test_eq10_latest_policy_grants_its_level_to_an_older_token(self, policy):
        dev, ps, p_read = policy
        ps.define(dev, "hospA", "doctor", "EHR", "write", T0 + 300)
        assert ps.check(dev.pseud, p_read, "EHR", "write", now=T0)
        assert not ps.check(dev.pseud, p_read, "EHR", "read", now=T0)

    def test_eq10_other_entities_policies_are_ignored(self, policy):
        dev, ps, p_ehr = policy
        ps.define(dev, "hospB", "nurse", "audit_logs", "read", T0 + 900)
        assert ps.check(dev.pseud, p_ehr, "EHR", "read", now=T0)

    def test_revocation_invalidates_only_that_entity_and_resource(self, policy, events):
        dev, ps, p_ehr = policy
        p_aud = ps.define(dev, "hospA", "doctor", "audit_logs", "read", T0 + 500)
        p_other = ps.define(dev, "hospB", "doctor", "EHR", "read", T0 + 500)
        ps.revoke(dev, "hospA", "EHR", now=T0 + 1)
        assert events[-1]["event"] == "policy_revoke"
        assert not ps.check(dev.pseud, p_ehr, "EHR", "read", now=T0)
        revoked = next(x for x in ps.pol[dev.pseud] if x["pi"][0] == "hospA" and x["pi"][2] == "EHR")
        assert revoked["pi"][4] == T0 + 1 and revoked["p"] != p_ehr
        assert ps.check(dev.pseud, p_aud, "audit_logs", "read", now=T0)
        assert ps.check(dev.pseud, p_other, "EHR", "read", now=T0)


# ---------------------------------------------------------------- RBAC baseline and the leakage metric (Sec 5.5)
class TestRBACAndLeakage:
    @pytest.mark.parametrize("role, action, ok", [("doctor", "read", True), ("doctor", "write", True), ("nurse", "write", False),
                                                  ("auditor", "audit", True), (None, "read", False)])
    def test_rbac_role_permissions(self, role, action, ok):
        rbac = AC.RBACContract()
        if role:
            rbac.assign("0xA", role)
        assert rbac.check_access("0xA", "patient-0002", action) is ok

    def test_rbac_events_expose_identity_and_role(self):
        rbac = AC.RBACContract()
        rbac.assign("0xHospA", "doctor")
        rbac.check_access("0xHospA", "patient-0002", "read")
        found = AC.identity_leakage(rbac.events, dict(patient_id="patient-0002", entity="0xHospA", role="doctor"))
        assert found == ["patient_id", "entity", "role"]

    def test_identity_leakage_handles_bytes_and_absent_values(self):
        secret = os.urandom(32)
        view = {"token": secret, "who": "abc123"}
        assert AC.identity_leakage(view, dict(s=secret, pid="patient-0001", who="abc123")) == ["s", "who"]
        assert AC.identity_leakage({"x": 1}, dict(pid="patient-0001")) == []

    def test_ledger_commitments_do_not_leak_but_requests_leak_s(self, setup):
        dev, ac, hosp, _, s = setup
        sensitive = dict(patient_id=PID, secret_s=s)
        assert AC.identity_leakage({"|".join(k): v for k, v in ac.commit.items()}, sensitive) == []
        assert AC.identity_leakage(req_at(hosp, dev, T0), sensitive) == ["secret_s"]


# ---------------------------------------------------------------- experiment drivers
def test_run_checks_passes(capsys):
    AC.run_checks()                                   # asserts all 20 paper behaviours internally
    out = capsys.readouterr().out
    assert out.count("PAPER-FLAW") == 3


@pytest.mark.filterwarnings("ignore::UserWarning")
def test_run_reports_the_paper_designs_security_metrics(monkeypatch, tmp_path):
    """Small run of run(): FN = 0 %, and exactly 2 of the 7 attack classes always succeed (FP = 2/7)."""
    monkeypatch.setitem(CFG, "AUTH_ROUNDS", 20)
    monkeypatch.setitem(CFG, "CRYPTO_ROUNDS", 2)
    monkeypatch.setitem(CFG, "N_RUNS", 2)
    monkeypatch.chdir(tmp_path)                      # figures are written here, not into the code folder
    for key in ("auth_ms", "rbac_ms", "fp", "fn", "proof_gen_ms"):
        monkeypatch.delitem(RESULTS, key, raising=False)
    AC.run({"enc": np.full(5, 0.05), "dec": np.full(5, 0.05)})
    assert RESULTS["fn"] == 0.0
    assert RESULTS["fp"] == pytest.approx(100 * 2 / 7)
    assert RESULTS["auth_ms"] > 0 and RESULTS["rbac_ms"] > 0 and RESULTS["proof_gen_ms"] > 0
    assert (tmp_path / "fig03_access_time.png").exists() and (tmp_path / "fig09_crypto_distribution.png").exists()
