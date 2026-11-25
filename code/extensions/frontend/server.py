"""Web front end for the baseline system (FastAPI): four portals with their own logins.

    pip install -r code/extensions/frontend/requirements.txt
    python code/extensions/frontend/server.py            # then open http://127.0.0.1:8000

Portals: /patient, /doctor, /hospital, /admin (each needs an account of that role, see demo_accounts.json), and / (landing).
The API drives one DemoSystem (system.py), built from the unchanged base modules in code/v2_components. Portal logins (auth.py) only
decide who may use which screen; the paper's own access control still decides every record release. Listens on 127.0.0.1 only: a
local demo with deliberately insecure (paper-faithful) cryptography, not a deployable service.

Abstraction: the patient, clinician and hospital routes return only what an ordinary hospital system would show (views.py): who
has access and whether a request was granted. Why a check passed or failed, and anything about the ledger, nodes, pseudonyms or
the dataset, is returned only on admin routes.
"""
import os, sys, time, pathlib, threading, subprocess
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import system as S                                                # also puts code/v2_components and the data layer on sys.path
import auth
import views as V

from typing import Literal
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

app = FastAPI(title="HealthSafe (baseline)", docs_url=None, redoc_url=None, openapi_url=None)
STATE = dict(sys=None, building=False, error=None)
BUILD_LOCK = threading.Lock()
MAX_BODY = 16 * 1024                                              # every API body is a few hundred bytes
CSRF_HEADER = "x-healthsafe"                                      # app.js sends it; a cross-site form cannot set custom headers
HOSPITAL = Literal["hospA", "hospB"]
RESOURCE = Literal["EHR", "audit_logs"]
ACCESS = Literal["read", "write"]
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
                               "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
}


from fastapi.exceptions import RequestValidationError


@app.exception_handler(RequestValidationError)
async def bad_input(request: Request, exc: RequestValidationError):
    """One readable sentence instead of FastAPI's list (which also echoed the input, so an Infinity broke the JSON)."""
    msgs = []
    for e in exc.errors()[:3]:
        field = ".".join(str(x) for x in e.get("loc", ())[1:]) or "body"
        msgs.append(f"{field}: {e.get('msg', 'invalid value')}")
    return JSONResponse({"detail": "; ".join(msgs) or "invalid request"}, 422)


@app.middleware("http")
async def guard(request: Request, call_next):
    """Body-size cap, CSRF check on state-changing API calls, and security headers on every response."""
    if request.method not in ("GET", "HEAD", "OPTIONS") and request.url.path.startswith("/api/"):
        if "chunked" in request.headers.get("transfer-encoding", "").lower():   # no length up front: a 400 MB body was read in full
            return JSONResponse({"detail": "chunked request bodies are not accepted"}, 411)
        try:
            if int(request.headers.get("content-length") or 0) > MAX_BODY:
                return JSONResponse({"detail": "request body too large"}, 413)
        except ValueError:
            return JSONResponse({"detail": "bad content-length"}, 400)
        if request.headers.get(CSRF_HEADER) != "1":
            return JSONResponse({"detail": "missing X-HealthSafe header"}, 403)
        origin = request.headers.get("origin")
        if origin and origin.rstrip("/") != f"{request.url.scheme}://{request.headers.get('host', '')}":
            return JSONResponse({"detail": "cross-origin request refused"}, 403)
    resp = await call_next(request)
    for k, v in SECURITY_HEADERS.items(): resp.headers.setdefault(k, v)
    if not request.url.path.startswith(("/api/", "/figures/")):    # pages and static files: always revalidate, so an updated
        resp.headers["Cache-Control"] = "no-cache"                # app.js is never mixed with a stale cached copy
    return resp
JOB = dict(running=False, started=None, finished=None, returncode=None, log=[])
ACCOUNTS = auth.Accounts()
COOKIE = "zk_sid"
BASE_OUT = S.BASE_DIR / "output"
WILDPPG_OUT = S.DATA_DIR / "output" / "wildppg_system"


def system():
    if STATE["sys"] is None:
        if STATE["error"]: raise HTTPException(503, STATE["error"])
        raise HTTPException(503, "system is still being built")
    return STATE["sys"]


def _call(fn, *a, **kw):
    """Run a system call and turn bad input into 400s instead of 500s."""
    try:
        return fn(*a, **kw)
    except (KeyError, ValueError, IndexError) as e:
        raise HTTPException(400, str(e).strip("'"))


# ------------------------------------------------------------------ auth
def need(*roles):
    def dep(request: Request):
        sid = request.cookies.get(COOKIE); u = ACCOUNTS.user(sid)
        if u is None: raise HTTPException(401, ACCOUNTS.why_out(sid) or "sign in first")
        if u["role"] not in roles: raise HTTPException(403, f"needs a {' or '.join(roles)} account")
        return u
    return dep


class LoginIn(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=128)
    portal: str = Field(max_length=16)


@app.post("/api/auth/login")
def login(body: LoginIn, request: Request, response: Response):
    if body.portal not in auth.ROLES: raise HTTPException(400, "unknown portal")
    try:
        sid, user = ACCOUNTS.login(body.username, body.password, body.portal, client=request.client.host if request.client else "?")
    except auth.Throttled as e:
        raise HTTPException(429, str(e))
    except PermissionError as e:
        raise HTTPException(401, str(e))
    response.set_cookie(COOKIE, sid, httponly=True, samesite="strict", max_age=auth.SESSION_TTL_S, path="/")
    return user


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    ACCOUNTS.logout(request.cookies.get(COOKIE)); response.delete_cookie(COOKIE, path="/")
    return dict(ok=True)


@app.get("/api/auth/me")
def me(request: Request):
    u = ACCOUNTS.user(request.cookies.get(COOKIE))
    if u is None: raise HTTPException(401, "not signed in")
    out = ACCOUNTS.public(u)
    if u["role"] == "patient" and STATE["sys"] is not None:
        try:
            out["label"] = STATE["sys"].label_of[STATE["sys"].pseud_at(u["patient_index"])]
        except KeyError:
            out["record_missing"] = True                          # the admin sees why (dataset page); the patient does not
    return out


@app.get("/api/status")
def status():
    """Public: is the system up, and which usernames exist per portal (no passwords)."""
    s = STATE["sys"]
    return dict(ready=s is not None, building=STATE["building"], hospitals=ACCOUNTS.hospitals,
                demo_users={r: ACCOUNTS.usernames(r) for r in auth.ROLES})


def _ctx(s):
    return dict(source=s.cfg["source"], source_desc=s.source_desc, chain_valid=s.chain_ok(), nodes=s.nodes(), dataset_id=s.built_at,
                hospitals=list(S.HOSPITALS), hospital_names={h: ACCOUNTS.hospitals.get(h, {}).get("name", h) for h in S.HOSPITALS})


@app.get("/api/context")
def context(u=Depends(need(*auth.ROLES))):
    """Shared header data. Only the admin gets the ledger, node and dataset state."""
    ctx = _ctx(system())
    return ctx if u["role"] == "admin" else V.context(ctx)


# ------------------------------------------------------------------ patient portal (own record only)
class PolicyIn(BaseModel):
    entity: HOSPITAL = "hospA"
    role: Literal["doctor", "nurse", "auditor"] = "doctor"
    resource: RESOURCE = "EHR"
    access: ACCESS = "read"
    ttl_s: float = Field(3600.0, ge=60, le=365 * 86400, allow_inf_nan=False)   # 1 minute to 1 year; inf/NaN broke JSON


class EntityIn(BaseModel):
    hospital: HOSPITAL = "hospA"
    resource: RESOURCE = "EHR"


class HospitalIn(BaseModel):
    hospital: HOSPITAL = "hospA"


OK = dict(ok=True)                                                # patient changes: no ledger or consensus detail


def _my_pseud(u):
    return _call(system().pseud_at, u["patient_index"])


@app.get("/api/patient")
def patient(u=Depends(need("patient"))):
    return V.patient(_call(system().patient_view, _my_pseud(u)))


@app.get("/api/patient/history")
def patient_history(u=Depends(need("patient"))):
    return V.patient_activity(system(), _my_pseud(u))


@app.post("/api/patient/share")
def share(body: PolicyIn, u=Depends(need("patient"))):
    """Give a hospital access: the consent token if it does not hold a valid one yet (Algs 3-4), then the policy (Eqs 8-9)."""
    s, p = system(), _my_pseud(u)
    if not s.token_valid(body.entity, p): _call(s.grant_token, p, body.entity)
    _call(s.define_policy, p, body.entity, body.role, body.resource, body.access, body.ttl_s)
    return OK


@app.post("/api/patient/withdraw")
def withdraw(body: HospitalIn, u=Depends(need("patient"))):
    """Withdraw every active permission a hospital holds (Sec 4.3.3 revocation, per resource)."""
    s, p, now = system(), _my_pseud(u), time.time()
    live = {e["pi"][2] for e in s.ps.pol.get(p, []) if e["pi"][0] == body.hospital and e["pi"][4] > now}
    if not live: raise HTTPException(400, "this hospital has no access to withdraw")
    for res in sorted(live): _call(s.revoke_policy, p, body.hospital, res)
    return OK


@app.post("/api/patient/grant")
def grant(body: EntityIn, u=Depends(need("patient"))):
    _call(system().grant_token, _my_pseud(u), body.hospital); return OK


@app.post("/api/patient/policy")
def policy(body: PolicyIn, u=Depends(need("patient"))):
    _call(system().define_policy, _my_pseud(u), body.entity, body.role, body.resource, body.access, body.ttl_s); return OK


@app.post("/api/patient/revoke-token")
def revoke_token(u=Depends(need("patient"))):
    _call(system().revoke_token, _my_pseud(u)); return OK


@app.post("/api/patient/revoke-policy")
def revoke_policy(body: EntityIn, u=Depends(need("patient"))):
    _call(system().revoke_policy, _my_pseud(u), body.hospital, body.resource); return OK


# ------------------------------------------------------------------ doctor portal (always as the doctor's own hospital)
class RequestIn(BaseModel):
    pseud: str = Field(max_length=64)
    resource: RESOURCE = "EHR"
    action: ACCESS = "read"


class TestRequestIn(RequestIn):                                   # admin only: the scenarios and attacks
    hospital: HOSPITAL = "hospA"
    corrupt_first: int = Field(0, ge=0, le=5)
    policy_from_ledger: bool = False


@app.get("/api/doctor/patients")
def doctor_patients(u=Depends(need("doctor"))):
    return V.doctor_patients(system().doctor_patients(u["hospital"]))


@app.post("/api/doctor/request")
def request_access(body: RequestIn, u=Depends(need("doctor"))):
    by = dict(username=u["username"], name=u["name"], role=u["staff_role"])
    return V.doctor_result(_call(system().request_access, u["hospital"], body.pseud, body.resource, body.action, 0, False, by))


@app.get("/api/doctor/history")
def doctor_history(u=Depends(need("doctor"))):
    return [V.request_row(r) for r in system().requests_by(u["username"])]


# ------------------------------------------------------------------ hospital portal (own hospital only)
@app.get("/api/hospital")
def hospital(u=Depends(need("hospital"))):
    v = V.hospital(system().hospital_view(u["hospital"]))
    v["staff"] = ACCOUNTS.staff(u["hospital"]); v["name"] = ACCOUNTS.hospitals.get(u["hospital"], {}).get("name", u["hospital"])
    return v


# ------------------------------------------------------------------ admin portal: dataset, consortium, ledger, users, lab
class ResetIn(BaseModel):
    source: Literal["synthetic", "wildppg"] = "synthetic"
    n_patients: int = 8
    n_steps: int = 100
    n_nodes: int = 7
    crashed: int = 1
    compromised: int = 1


ADMIN = Depends(need("admin"))


@app.get("/api/admin/overview")
def overview(u=ADMIN):
    return system().overview()


@app.get("/api/admin/dataset")
def dataset(u=ADMIN):
    ok, names = S.wildppg_available(); s = STATE["sys"]
    return dict(current=None if s is None else dict(s.cfg, source_desc=s.source_desc, patients=s.patients()),
                building=STATE["building"], wildppg=dict(available=ok, participants=names),
                limits=dict(n_patients=[2, 16], n_steps=[20, 400], n_nodes=[4, 31]))


@app.post("/api/admin/dataset")
def reset(body: ResetIn, u=ADMIN):
    if not 2 <= body.n_patients <= 16 or not 20 <= body.n_steps <= 400 or not 4 <= body.n_nodes <= 31:
        raise HTTPException(400, "patients 2-16, steps 20-400, nodes 4-31")
    if body.crashed < 0 or body.compromised < 0 or body.crashed + body.compromised > body.n_nodes or body.crashed >= body.n_nodes:
        raise HTTPException(400, "crashed + compromised must not exceed the nodes, and at least one node must be alive")
    if body.n_nodes - body.crashed < body.n_nodes // 2 + 1:
        raise HTTPException(400, f"{body.n_nodes - body.crashed} of {body.n_nodes} nodes alive is below the quorum of "
                                 f"{body.n_nodes // 2 + 1}: nothing (not even consent) could be committed. Crash fewer nodes.")
    if not BUILD_LOCK.acquire(blocking=False): raise HTTPException(409, "a dataset is already loading")
    STATE["building"] = True
    try:
        new = S.DemoSystem(**body.model_dump())                   # build aside, then swap in one step: no half-built system is seen
        STATE["sys"] = new; STATE["error"] = None
    except Exception as e:
        raise HTTPException(400, f"could not load the dataset: {e}")
    finally:
        STATE["building"] = False; BUILD_LOCK.release()
    return new.overview()


@app.get("/api/admin/users")
def users(u=ADMIN):
    return ACCOUNTS.listing()


@app.post("/api/admin/users/{username}/{action}")
def user_action(username: str, action: Literal["disable", "enable"], u=ADMIN):
    if action not in ("disable", "enable"): raise HTTPException(400, "action must be disable or enable")
    return _call(ACCOUNTS.set_disabled, username, action == "disable")


@app.get("/api/admin/ledger")
def ledger(u=ADMIN):
    return system().ledger()


@app.get("/api/admin/block/{i}")
def block(i: int, u=ADMIN):
    return _call(system().block, i)


@app.post("/api/admin/block/{i}/tamper")
def tamper(i: int, u=ADMIN):
    return _call(system().tamper, i)


@app.post("/api/admin/block/{i}/restore")
def restore(i: int, u=ADMIN):
    return _call(system().restore, i)


@app.post("/api/admin/node/{i}/{action}")
def node(i: int, action: str, u=ADMIN):
    return _call(system().node_action, i, action)


@app.get("/api/admin/audit")
def audit(u=ADMIN):
    return system().audit()


@app.get("/api/admin/requests")
def all_requests(u=ADMIN):
    """Every access request from every hospital, with the checks and the reason for the decision."""
    return system().all_requests()


@app.post("/api/admin/request")
def test_request(body: TestRequestIn, u=ADMIN):
    """Send a request as any hospital, including the corrupted-transmission and ledger-copied-token scenarios; full detail back."""
    by = dict(username=u["username"], name=u["name"], role="admin test")
    return _call(system().request_access, body.hospital, body.pseud, body.resource, body.action, body.corrupt_first,
                 body.policy_from_ledger, by)


class NIn(BaseModel):
    n: int = 100


class ConsIn(BaseModel):
    proto: str = "Raft"
    n: int = 50
    mode: str = "normal"
    rounds: int = 30
    crashed: int = 0


LAB_LOCK = threading.Lock()


def _lab(fn, *a):
    """One lab job at a time, so repeated clicks cannot pile up CPU-heavy benchmarks."""
    if not LAB_LOCK.acquire(blocking=False): raise HTTPException(409, "another lab run is in progress")
    try:
        return fn(*a)
    finally:
        LAB_LOCK.release()


@app.post("/api/lab/attacks")
def attacks(body: NIn, u=ADMIN):
    return _lab(S.attack_suite, max(10, min(body.n, 1000)))


@app.post("/api/lab/bench/verify")
def bench_verify(body: NIn, u=ADMIN):
    return _lab(S.bench_verify, max(10, min(body.n, 2000)))


@app.post("/api/lab/bench/crypto")
def bench_crypto(body: NIn, u=ADMIN):
    return _lab(S.bench_crypto, max(10, min(body.n, 500)))


@app.post("/api/lab/bench/consensus")
def bench_consensus(body: ConsIn, u=ADMIN):
    if body.proto not in ("Raft", "PBFT", "HotStuff", "Tendermint"): raise HTTPException(400, "unknown protocol")
    if body.mode not in ("normal", "failover", "congestion"): raise HTTPException(400, "unknown mode")
    top = 300 if body.proto == "PBFT" else 1000                  # PBFT is O(n^2) messages: n=1000 x 200 rounds held a worker 71 s
    if not 4 <= body.n <= top or not 1 <= body.rounds <= 50 or not 0 <= body.crashed < body.n:
        raise HTTPException(400, f"nodes 4-{top} for {body.proto}, rounds 1-50, crashed fewer than nodes")
    return _lab(S.bench_consensus, body.proto, body.n, body.mode, body.rounds, body.crashed)


def _run_experiments():
    JOB.update(running=True, started=time.time(), finished=None, returncode=None, log=[])
    env = dict(os.environ, MPLBACKEND="Agg", PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    try:
        p = subprocess.Popen([sys.executable, "main.py"], cwd=S.BASE_DIR, env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
        for line in p.stdout:
            JOB["log"].append(line.rstrip()); JOB["log"] = JOB["log"][-400:]
        JOB["returncode"] = p.wait()
    except Exception as e:
        JOB["log"].append(f"failed to start: {e}"); JOB["returncode"] = -1
    finally:
        JOB.update(running=False, finished=time.time())


@app.post("/api/lab/experiments/run")
def run_experiments(u=ADMIN):
    if JOB["running"]: raise HTTPException(409, "already running")
    threading.Thread(target=_run_experiments, daemon=True).start()
    return dict(started=True)


@app.get("/api/lab/experiments/status")
def experiments_status(u=ADMIN):
    return dict(running=JOB["running"], started=JOB["started"], finished=JOB["finished"], returncode=JOB["returncode"],
                log=JOB["log"][-60:])


@app.get("/api/lab/figures")
def figures(u=ADMIN):
    def ls(d, prefix):
        return [dict(name=f.name, url=f"{prefix}/{f.name}", mtime=f.stat().st_mtime) for f in sorted(d.glob("*.png"))] if d.exists() else []
    return dict(base=ls(BASE_OUT, "/figures/base"), wildppg=ls(WILDPPG_OUT, "/figures/wildppg"))


@app.get("/figures/{which}/{name}")
def figure(which: str, name: str, u=ADMIN):
    d = {"base": BASE_OUT, "wildppg": WILDPPG_OUT}.get(which)
    f = (d / name) if d else None
    if f is None or not name.endswith(".png") or f.resolve().parent != d.resolve() or not f.exists():
        raise HTTPException(404, "no such figure")
    return FileResponse(f)


# ------------------------------------------------------------------ pages
app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")


@app.get("/")
def landing():
    return FileResponse(HERE / "static" / "index.html")


@app.get("/{portal}")
def portal(portal: str):
    if portal not in auth.ROLES: raise HTTPException(404, "no such page")
    return FileResponse(HERE / "static" / "portal.html")


def _build_default():
    try:
        STATE["sys"] = S.DemoSystem()
    except Exception as e:
        STATE["error"] = f"could not build the default system: {e}"


if __name__ == "__main__":
    import uvicorn
    threading.Thread(target=_build_default, daemon=True).start()
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PORT", 8000)))
