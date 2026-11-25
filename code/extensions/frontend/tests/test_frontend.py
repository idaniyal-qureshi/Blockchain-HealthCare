"""Tests for the baseline web front end: the system layer (system.py) and the HTTP API (server.py).

    python -m pytest code/extensions/frontend/tests -q

The system tests pin the paper-faithful behaviour the UI shows: valid access, Algorithm 4 retry, revocation, the two paper flaws,
tamper detection and loss of quorum. WildPPG tests skip themselves when the extracted window files are absent.
"""
import json, pathlib, sys
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import system as S                                                # noqa: E402

WILDPPG, _ = S.wildppg_available()


@pytest.fixture
def sy():
    return S.DemoSystem(source="synthetic", n_patients=3, n_steps=40)


def strict_json(obj):
    json.dumps(obj, allow_nan=False)                              # what the web server's encoder requires


def test_build_commits_consent_and_records(sy):
    ov = sy.overview()
    assert ov["chain_valid"] and ov["block_kinds"]["audit"] >= 1 and ov["block_kinds"]["records"] >= 1
    assert len(ov["patients"]) == 3
    strict_json(ov)


def test_valid_request_releases_the_record(sy):
    p = sy.patients()[0]["pseud"]
    r = sy.request_access("hospA", p)
    assert r["granted"] and r["token"]["passed"] and r["policy"]["passed"]
    assert r["ledger"]["block"] is not None and len(r["record"]["hr"]) == 40
    strict_json(r)


def test_algorithm4_retry_and_give_up(sy):
    p = sy.patients()[0]["pseud"]
    ok = sy.request_access("hospA", p, corrupt_first=2)
    assert ok["granted"] and len(ok["token"]["attempts"]) == 3
    no = sy.request_access("hospA", p, corrupt_first=3)
    assert not no["granted"] and len(no["token"]["attempts"]) == 3


def test_denials(sy):
    p = sy.patients()[0]["pseud"]
    assert not sy.request_access("hospB", p)["granted"]                       # no consent
    assert not sy.request_access("hospA", p, action="write")["granted"]       # level enforced
    assert not sy.request_access("hospA", p, resource="audit_logs")["granted"]


def test_paper_flaw_ledger_policy_token_is_accepted(sy):
    p = sy.patients()[0]["pseud"]
    assert sy.request_access("hospA", p, policy_from_ledger=True)["granted"]  # Eq 9: p is on the ledger


def test_revocations(sy):
    p = sy.patients()[0]["pseud"]
    sy.revoke_token(p)
    assert not sy.request_access("hospA", p)["granted"]
    sy.grant_token(p, "hospA")
    assert sy.request_access("hospA", p)["granted"]
    sy.revoke_policy(p, "hospA", "EHR")
    assert not sy.request_access("hospA", p)["granted"]


def test_new_hospital_after_grant_and_policy(sy):
    p = sy.patients()[0]["pseud"]
    sy.grant_token(p, "hospB"); sy.define_policy(p, "hospB", "nurse", "EHR", "read", 600)
    assert sy.request_access("hospB", p)["granted"]
    with pytest.raises(ValueError):
        sy.define_policy(p, "hospB", "nurse", "EHR", "none", 600)


def test_tamper_and_restore(sy):
    assert sy.ledger()["valid"]
    assert not sy.tamper(2)["valid"]
    assert sy.restore(2)["valid"]


def test_no_quorum_stops_commits(sy):
    for i in range(sy.cluster.n): sy.node_action(i, "crash")
    r = sy.request_access("hospA", sy.patients()[0]["pseud"])
    assert r["ledger"]["block"] is None and "quorum" in r["ledger"]["error"]


def test_audit_has_no_patient_identity(sy):
    sy.request_access("hospA", sy.patients()[0]["pseud"])
    a = sy.audit()
    assert a["total"] > 0 and not a["identity_on_ledger"]


def test_attack_suite_reproduces_the_paper():
    r = S.attack_suite(20)
    flaws = {x["attack"] for x in r["rows"] if x["paper_flaw"]}
    assert flaws == {"Captured token with fresh nonce/timestamp", "Policy token copied from the ledger"}
    assert r["fn_rate"] == 0 and round(r["fp_rate"], 2) == 28.57


def test_benchmarks_run():
    assert S.bench_verify(20)["auth"]["mean"] > 0
    assert len(S.bench_crypto(5)["schemes"]) == 3
    c = S.bench_consensus("Raft", 9, "normal", 3, 5)                          # 4 of 9 alive < quorum 5
    assert c["committed"] == 0


@pytest.mark.skipif(not WILDPPG, reason="WildPPG window files not extracted")
def test_wildppg_source_is_strict_json_and_has_truth():
    sy = S.DemoSystem(source="wildppg", n_patients=2, n_steps=40)
    p = sy.patients()[0]["pseud"]
    v = sy.patient_view(p); strict_json(v)
    assert v["vitals"]["truth"] is not None
    r = sy.request_access("hospA", p); strict_json(r)
    assert r["granted"] and r["record"]["truth"] is not None


def test_hospital_log_and_patient_history(sy):
    p = sy.patients()[0]["pseud"]
    sy.request_access("hospA", p, by=dict(username="dr.x", name="Dr X", role="doctor"))
    sy.request_access("hospB", p, by=dict(username="dr.y", name="Dr Y", role="doctor"))
    hv = sy.hospital_view("hospA")
    assert hv["stats"]["requests"] == 1 and hv["stats"]["granted"] == 1 and hv["stats"]["consenting"] == 3
    assert sy.hospital_view("hospB")["stats"]["consenting"] == 0
    assert [r["hospital"] for r in sy.requests_by("dr.y")] == ["hospB"]
    events = {e["event"] for e in sy.patient_history(p)["events"]}
    assert {"grant", "policy_define", "allow", "deny"} <= events
    with pytest.raises(KeyError):
        sy.pseud_at(3)


# ---------------------------------------------------------------------- HTTP API with portal logins
SEED = json.loads((pathlib.Path(__file__).resolve().parents[1] / "demo_accounts.json").read_text(encoding="utf-8"))
PW = {a["username"]: a["password"] for a in SEED["accounts"]}


@pytest.fixture(scope="module")
def srv():
    pytest.importorskip("httpx")                                  # FastAPI's TestClient needs it
    import server
    server.STATE["sys"] = S.DemoSystem(source="synthetic", n_patients=3, n_steps=40)
    return server


def client(srv, user=None, portal=None):
    from fastapi.testclient import TestClient
    c = TestClient(srv.app, headers={"X-HealthSafe": "1"})         # app.js sends this on every call (CSRF guard)
    if user:
        r = c.post("/api/auth/login", json=dict(username=user, password=PW[user], portal=portal))
        assert r.status_code == 200, r.text
    return c


def test_login_rules(srv):
    c = client(srv)
    assert c.get("/api/patient").status_code == 401
    assert c.post("/api/auth/login", json=dict(username="dr.sana", password="wrong", portal="doctor")).status_code == 401
    assert c.post("/api/auth/login", json=dict(username="dr.sana", password=PW["dr.sana"], portal="admin")).status_code == 401
    assert "password" not in json.dumps(c.get("/api/status").json())
    assert c.get("/").status_code == 200 and c.get("/doctor").status_code == 200 and c.get("/nowhere").status_code == 404


def test_roles_are_enforced(srv):
    doc = client(srv, "dr.sana", "doctor")
    assert doc.get("/api/admin/ledger").status_code == 403
    assert doc.post("/api/admin/dataset", json=dict(source="synthetic")).status_code == 403
    assert doc.get("/api/patient").status_code == 403
    assert doc.get("/figures/base/x.png").status_code == 403
    pat = client(srv, "patient1", "patient")
    assert pat.post("/api/doctor/request", json=dict(pseud="x")).status_code == 403


def test_patient_sees_only_own_record(srv):
    pat = client(srv, "patient2", "patient")
    sy = srv.STATE["sys"]; me = pat.get("/api/auth/me").json()
    assert me["label"] == sy.label_of[sy.pseud_at(1)] and "pseud" not in me
    assert pat.get("/api/patient").json()["label"] == me["label"]
    p8 = client(srv, "patient8", "patient")                                  # only 3 patients loaded
    assert p8.get("/api/auth/me").json()["record_missing"] and p8.get("/api/patient").status_code == 400


def test_doctor_requests_as_own_hospital(srv):
    p = srv.STATE["sys"].pseud_at(0)
    a = client(srv, "dr.sana", "doctor").post("/api/doctor/request", json=dict(pseud=p)).json()
    b = client(srv, "dr.bilal", "doctor").post("/api/doctor/request", json=dict(pseud=p, hospital="hospA")).json()
    assert a["status"] == "granted" and a["record"]["hr"]
    assert b["status"] == "denied" and "record" not in b                    # the body cannot pick another hospital
    log = client(srv, "admin", "admin").get("/api/admin/requests").json()["requests"]
    assert {r["by"]["username"]: r["hospital"] for r in log[:2]} == {"dr.bilal": "hospB", "dr.sana": "hospA"}
    h = client(srv, "hospa.admin", "hospital").get("/api/hospital").json()
    assert h["hospital"] == "hospA" and any(r["by"]["username"] == "dr.sana" for r in h["requests"])
    assert not any(r["by"]["username"] == "dr.bilal" for r in h["requests"])


def test_admin_dataset_users_and_disable(srv):
    adm = client(srv, "admin", "admin")
    assert adm.post("/api/admin/dataset", json=dict(n_patients=99)).status_code == 400
    assert adm.post("/api/admin/dataset", json=dict(source="synthetic", n_patients=4, n_steps=40)).status_code == 200
    assert len(adm.get("/api/admin/dataset").json()["current"]["patients"]) == 4
    nurse = client(srv, "nurse.amna", "doctor")
    assert adm.post("/api/admin/users/nurse.amna/disable").status_code == 200
    assert nurse.get("/api/doctor/patients").status_code == 401                # signed out everywhere
    assert client(srv).post("/api/auth/login", json=dict(username="nurse.amna", password=PW["nurse.amna"], portal="doctor")).status_code == 401
    adm.post("/api/admin/users/nurse.amna/enable")
    assert adm.post("/api/admin/users/admin/disable").status_code == 400
    assert adm.get("/figures/base/../server.py").status_code == 404


# ---------------------------------------------------------------------- fixes from the stress test
def test_bad_policy_values_are_refused(srv):
    pat = client(srv, "patient1", "patient")
    for body in ('{"entity":"hospA","ttl_s":Infinity}', '{"entity":"hospA","ttl_s":NaN}', '{"entity":"hospA","ttl_s":-5}',
                 '{"entity":"nowhere"}', '{"entity":"hospA","resource":"' + "x" * 5000 + '"}'):
        r = pat.post("/api/patient/policy", content=body, headers={"Content-Type": "application/json"})
        assert r.status_code == 422, body[:40]
    assert pat.get("/api/patient").status_code == 200                       # nothing broke the record's JSON
    assert "nowhere" not in srv.STATE["sys"].hospitals


def test_csrf_size_and_headers(srv):
    from fastapi.testclient import TestClient
    pat = client(srv, "patient1", "patient")
    bare = TestClient(srv.app); bare.cookies = pat.cookies                 # same session, no X-HealthSafe header
    assert bare.post("/api/patient/revoke-token").status_code == 403
    assert pat.post("/api/patient/revoke-token", headers={"Origin": "http://evil.test"}).status_code == 403
    assert pat.post("/api/patient/grant", content="x" * 20000, headers={"Content-Type": "application/json"}).status_code == 413
    r = pat.get("/api/patient")
    assert r.headers["X-Frame-Options"] == "DENY" and "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert pat.get("/openapi.json").status_code == 404


def test_login_throttle():
    import auth
    a = auth.Accounts()
    for _ in range(auth.FAIL_LIMIT_USER):
        with pytest.raises(PermissionError): a.login("dr.hamza", "wrong", "doctor", client="1.2.3.4")
    with pytest.raises(auth.Throttled): a.login("dr.hamza", PW["dr.hamza"], "doctor", client="1.2.3.4")
    with pytest.raises(PermissionError, match="an admin account"): a.login("admin", PW["admin"], "doctor", client="5.6.7.8")


def test_no_release_without_a_ledger_commit(sy):
    p = sy.patients()[0]["pseud"]
    for i in range(sy.cluster.n): sy.node_action(i, "crash")
    r = sy.request_access("hospA", p)
    assert not r["granted"] and "record" not in r and "ledger" in r["reason"]
    assert not sy.audit_buf                                       # refused up front: no audit backlog piles up


def test_incremental_scans_match_full_verify(sy):
    for _ in range(5): sy.request_access("hospA", sy.patients()[0]["pseud"])
    assert sy.chain_ok() == sy.chain.verify() is True
    sy.tamper(3); assert sy.chain_ok() == sy.chain.verify() is False
    sy.restore(3); assert sy.chain_ok() == sy.chain.verify() is True
    full = sum(len(b.metadata["tx"]) for b in sy.chain.blocks if b.metadata.get("kind") == "audit")
    assert sy.audit()["total"] == full and not sy.audit()["identity_on_ledger"]


def test_parallel_guesses_cannot_beat_the_throttle():
    import auth, threading
    a = auth.Accounts(); out = []
    def guess():
        try: a.login("dr.sana", "wrong", "doctor"); out.append("ok")
        except auth.Throttled: out.append("429")
        except PermissionError: out.append("401")
    ts = [threading.Thread(target=guess) for _ in range(30)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert out.count("401") <= auth.FAIL_LIMIT_USER


def test_chunked_body_refused(srv):
    pat = client(srv, "patient1", "patient")
    r = pat.post("/api/patient/grant", content=iter([b'{"hospital":', b'"hospA"}']), headers={"Content-Type": "application/json"})
    assert r.status_code == 411


def test_denial_reasons_and_live_policy_flag(sy):
    p = sy.patients()[0]["pseud"]
    assert "write on EHR" in sy.request_access("hospA", p, action="write")["reason"]
    assert "consent token" in sy.request_access("hospB", p)["reason"]
    assert sy.doctor_patients("hospA")[0]["policy_held"]
    sy.revoke_policy(p, "hospA", "EHR")
    assert not sy.doctor_patients("hospA")[0]["policy_held"]
    assert not sy.hospital_view("hospA")["patients"][0]["readable"]
    with pytest.raises(KeyError): sy.grant_token(p, "nowhere")


def test_only_the_admin_sees_why_and_the_ledger(srv):
    """Patients, clinicians and hospitals get plain outcomes; reasons, checks, ledger, nodes and dataset are admin-only."""
    sy = srv.STATE["sys"]; p = sy.pseud_at(0)
    doc = client(srv, "dr.sana", "doctor")
    r = doc.post("/api/doctor/request", json=dict(pseud=p, action="write", corrupt_first=5, policy_from_ledger=True)).json()
    assert r["status"] == "denied"                                          # write not allowed; attack knobs ignored
    assert sy.requests[-1]["corrupt_first"] == 0 and not sy.requests[-1]["ledger_copied"]
    pat = client(srv, "patient1", "patient"); hos = client(srv, "hospa.admin", "hospital")
    seen = [r, doc.get("/api/doctor/patients").json(), doc.get("/api/doctor/history").json(), doc.get("/api/context").json(),
            pat.get("/api/patient").json(), pat.get("/api/patient/history").json(), pat.get("/api/context").json(),
            hos.get("/api/hospital").json(), hos.get("/api/context").json(), pat.get("/api/auth/me").json()]
    text = json.dumps(seen)
    for key in ("reason", "token", "policy", "ledger", "block", "nodes", "chain_valid", "source", "pseud", "attempts", "governing", "held_by"):
        assert f'"{key}' not in text, key
    adm = client(srv, "admin", "admin")
    full = adm.get("/api/admin/requests").json()["requests"][0]
    assert "write on EHR" in full["reason"] and full["outcome"] == "denied" and "block" in full
    t = adm.post("/api/admin/request", json=dict(hospital="hospA", pseud=p, policy_from_ledger=True)).json()
    assert t["granted"] and t["policy"]["source"] == "copied from the ledger"   # the paper flaw, shown to the admin only
    assert "nodes" in adm.get("/api/context").json()


def test_patient_share_and_withdraw(srv):
    pat = client(srv, "patient2", "patient")
    hb = lambda: next(h for h in pat.get("/api/patient").json()["hospitals"] if h["hospital"] == "hospB")
    assert not hb()["has_access"]
    assert pat.post("/api/patient/share", json=dict(entity="hospB", ttl_s=86400)).json() == {"ok": True}
    assert hb()["has_access"] and hb()["current"]["status"] == "active"
    assert client(srv, "dr.bilal", "doctor").post("/api/doctor/request", json=dict(pseud=srv.STATE["sys"].pseud_at(1))).json()["status"] == "granted"
    assert pat.post("/api/patient/withdraw", json=dict(hospital="hospB")).status_code == 200
    assert not hb()["has_access"] and pat.post("/api/patient/withdraw", json=dict(hospital="hospB")).status_code == 400
    texts = [e["text"] for e in pat.get("/api/patient/history").json()["events"]]
    assert "You gave a hospital access" in texts and "You withdrew a hospital's access" in texts
    assert any(t.startswith("A hospital was allowed to view") for t in texts)
