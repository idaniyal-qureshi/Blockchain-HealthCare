# HealthSafe: the baseline's web front end

A browser front end for the **baseline system** (Hao et al. 2025, PLOS ONE e0332887), as implemented in `code/v2_components`.
It drives the real base modules step by step, the same way `blockchain.run_pipeline` does:

- `MockKyber`
- `Chain`
- `ConsensusCluster`
- the hash-commitment access control
- `PolicyStore`
- `SmartContractEngine`

Nothing in `code/v2_components` is modified.

> **Baseline mode.** The portals show the paper's system *as the paper describes it*, flaws included. A captured token replayed
> with a fresh nonce, and a policy token copied from the ledger, are both **accepted**.

## Run

```powershell
pip install -r code/v2_components/requirements.txt -r code/extensions/frontend/requirements.txt
python code/extensions/frontend/server.py
```

Open <http://127.0.0.1:8000>. The landing page links to the four portals. Each portal has its own sign-in:

| Portal | URL | Demo accounts | What it does |
|---|---|---|---|
| **Patient** | `/patient` | `patient1` … `patient8` | Shows the wearable's vitals: the corrected heart rate, quarantined readings marked, and the ECG truth on WildPPG. The patient grants or revokes a hospital's consent token (Algs 3-4) and defines or revokes policies (Eqs 8-10). The ledger-history screen shows everything the chain records about them, which is pseudonym only. |
| **Clinician** | `/doctor` | `dr.sana`, `dr.hamza`, `nurse.amna` (hospA); `dr.bilal` (hospB) | Requests a record, **always as the clinician's own hospital**. The decision is shown step by step: the token check with retries, the policy check, the consensus commit, then decryption. It also has a patient list with consent status and the clinician's request history. |
| **Hospital** | `/hospital` | `hospa.admin`, `hospb.admin` | Covers one hospital: its consenting patients and the policies it holds, its staff, and its access log. The access log is the hospital's own off-chain record of who asked for what, because the ledger stores only pseudonyms. |
| **Admin** | `/admin` | `admin` | Runs the consortium. **Loads the dataset** (synthetic or WildPPG, with patients, readings and cluster size), which rebuilds the ledger. It also covers: crashing, recovering or compromising nodes; browsing the ledger and tampering with or restoring blocks; the audit trail and contract events; enabling or disabling portal accounts; the attack and benchmark lab; and the full paper experiments with their figures. |

The demo passwords are in `demo_accounts.json`. They are demo-only test values: the server hashes them with PBKDF2-SHA256 at
start-up and never returns them. Patient accounts map to patients **by position**, so `patient1` is the first patient of whichever
dataset is loaded. All names are fictional.

### What the logins do and don't do

The portal logins live in `auth.py`. Sessions use a random id held in server memory and sent as an HttpOnly, SameSite=Strict
cookie. The logins decide who may use which screen:

- a patient only ever sees and changes their own record;
- a clinician can only request as their own hospital;
- a hospital only sees its own patients and log;
- only the admin can load data, touch nodes or the ledger, or run the lab.

Every rule is enforced by the server, not only by the page. Logins **don't** replace the paper's access control. Even a signed-in
clinician gets a record only if the patient's token, the patient's policy and the consensus commit all allow it.

The server listens on 127.0.0.1 only. Sessions are in memory, so restarting the server signs everyone out.

### Hardening (from the stress test)

Six parallel testers (security, load, and one per portal) found issues, which were then fixed:

- **Input validation:** every body is a fixed schema. Hospital, resource, access and role come from fixed lists, and policy validity must be 1 minute to 1 year (an `Infinity` TTL used to break three portals). Bodies are capped at 16 KB, and chunked bodies are refused. Validation errors are one readable sentence.
- **CSRF:** every state-changing call needs the `X-HealthSafe` header and a same-origin `Origin`.
- **Security headers:** a CSP with no inline scripts, `X-Frame-Options: DENY`, `nosniff` and `no-referrer`. The OpenAPI schema is not published.
- **Logins:**
  - After 5 failed sign-ins, the account locks for 60 s. Each attempt is reserved before the password hash runs, so parallel guesses can't slip through.
  - Each user keeps at most 5 sessions, and expired sessions are cleaned up.
  - A disabled user is told why they were signed out.
- **Release:** a record is released only after the access decision is committed to the ledger. With no quorum, requests are refused before any check runs. A ciphertext that fails its integrity check after a tamper is reported, not released.
- **Load:** chain validity, the audit trail and the identity-leak check are worked out incrementally rather than by re-hashing the whole chain on every page. The ledger and history pages send at most a few hundred rows, and lab benchmarks run one at a time. At 10,000 requests, the ledger page fell from 382 ms (1.5 MB) to 15 ms (48 KB). A clinician's request while six admins hammer the heavy pages fell from 4-5 s to about 40 ms.

**Left as the paper has them, but explained in the UI:**

- The policy's *role* is not checked.
- A hospital is governed by its latest-expiring policy (Eq. 10), so a new policy replaces the current one whatever it covers.
- Patient accounts map to dataset positions.
- A dataset reload starts a fresh ledger and request log.

## Files

- `server.py`: the FastAPI app. It serves the API under `/api` (with a role check on every route), the pages `/`, `/patient`, `/doctor`, `/hospital` and `/admin`, and the figures.
- `auth.py`: demo accounts, password hashing and sessions.
- `demo_accounts.json`: the demo account seed and the hospital names.
- `system.py`: `DemoSystem`, the stateful baseline. It also holds the hospital, patient and doctor views and the lab functions. It contains no web code.
- `static/index.html`: the landing page.
- `static/portal.html` + `app.js`: the four portals. The URL picks which one is shown.
- `static/styles.css`: the styles.
- `static/art/`: the minimal vector illustrations, one per section: patient wearable, clinician record, hospital, validator network, landing chain and sealed record. They were drawn for this app, so no third-party images or credits are needed.
- `tests/test_frontend.py`: tests for the system layer and the API, including the login and role rules.

## Tests

```powershell
pip install pytest httpx
python -m pytest code/extensions/frontend/tests -q
```

The tests pin the paper-faithful behaviour: valid access, Algorithm 4's retry, denials, both paper flaws, revocation, tampering,
loss of quorum, no identity on the ledger, the attack suite's 28.57% FP / 0% FN, and strict JSON.

They also pin the portal rules:

- a wrong password or the wrong portal is refused;
- each role is kept to its own endpoints;
- a patient sees only their own record;
- a clinician can't request as another hospital;
- the admin can load datasets and disable accounts, and a disabled account is signed out everywhere.
