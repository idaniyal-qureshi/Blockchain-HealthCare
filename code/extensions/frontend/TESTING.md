# Testing the HealthSafe front end

A short checklist for teammates. It takes about 15 minutes.

## 1. Get the code

```powershell
git fetch origin
git checkout main
git pull
```

Before the PR is merged, check out `feature/frontend` instead of `main`.

## 2. Install (Python 3.10 or newer)

```powershell
pip install -r code/v2_components/requirements.txt -r code/extensions/frontend/requirements.txt pytest httpx
```

## 3. Run the automated tests

```powershell
python -m pytest code/extensions/frontend/tests -q
```

Expected: **28 passed, 1 skipped**. The skipped test needs the WildPPG data, which is not in git.

## 4. Start the app

```powershell
python code/extensions/frontend/server.py
```

Open <http://127.0.0.1:8000>. The usernames and passwords are in `code/extensions/frontend/demo_accounts.json`.

> **Blank screen after signing in?** Your browser is using an old cached copy from an earlier version. Press F12, right-click the
> reload button, and choose **Empty cache and hard reload**. You only need to do this once.

## 5. Manual checks

Do them in order: later checks build on earlier ones. Restart the server first so you start from a fresh state.

### Patient, clinician and hospital: plain hospital-system screens

| # | Portal (account) | Do this | Expect |
|---|---|---|---|
| 1 | Clinician (`dr.bilal`, Riverside) | Open patient-0001's health record | **Access denied**, with no reason given |
| 2 | Patient (`patient1`) | Sharing → give **Riverside Medical Centre** access: Doctors, Health record, View, 1 day | Riverside shows "can see your record" |
| 3 | Clinician (`dr.bilal`) | Open patient-0001's health record again | **Access granted**, and the heart-rate chart draws in |
| 4 | Clinician (`dr.bilal`) | Patients | patient-0001 shows "you can open it" |
| 5 | Hospital (`hospb.admin`) | Patients, then Access log | patient-0001 is "shared"; the log shows the denied and the granted request, with **no reasons** |
| 6 | Patient (`patient1`) | Activity | "You gave a hospital access", "A hospital was allowed to view your health record"; **no hospital names, no reasons** |
| 7 | Patient (`patient1`) | Sharing → **Withdraw** Riverside, then `dr.bilal` opens the record again | **Access denied** |
| 8 | Patient (`patient1`) | Sharing → **Stop sharing** with every hospital, then `dr.sana` (Northgate) opens the record | **Access denied** |

Nowhere in the patient, clinician or hospital portals should you see the words ledger, block, node, consensus, token, policy
check, pseudonym, dataset or "baseline", or any status pills at the top right. If you do, report it.

### Admin: where the detail lives

| # | Do this (account `admin`) | Expect |
|---|---|---|
| 9 | Access requests | Every request from checks 1-8, each with its token and policy checks, a plain-language reason and a ledger block |
| 10 | Access requests → **Valid request** | Step-by-step decision: token, policy, consensus commit, decryption |
| 11 | Access requests → **Attack: ledger-copied policy token** | **Granted**, marked as a paper flaw (this is by design: it is one of the paper's two flaws) |
| 12 | Nodes & consensus → crash nodes until "No quorum", then a clinician opens a record | The clinician sees **Try again later**; the admin's Access requests shows why (no quorum). Then click **Recover all** |
| 13 | Ledger → **Tamper** with a block | Pill shows **Chain broken**. **Restore** → **Chain valid** |
| 14 | Attack lab → Run attacks | 28.57% false positives (the two paper flaws), 0% false negatives |
| 15 | Dataset → load with different settings | Other open portals show an "updated" banner; the request log starts fresh |
| 16 | Accounts → disable `nurse.amna` | She is signed out and cannot sign in until enabled again |

### Sign-in rules

| # | Do this | Expect |
|---|---|---|
| 17 | Sign in to the wrong portal, e.g. a patient account on `/doctor` | Refused, with a link to the right portal |
| 18 | Enter a wrong password 5 times for one account | That account is locked for 60 s |

### Look and feel

| # | Do this | Expect |
|---|---|---|
| 19 | Click buttons and switch screens | Buttons press down with a ripple; busy buttons show a spinner; screens slide in; nothing stays blank |
| 20 | Make the window narrow (phone width) | The layout stacks; nothing is cut off |

## Good to know

- Everything is kept in memory. Restarting the server signs everyone out and resets all state.
- Patient accounts map to dataset positions: `patient1` is the first patient of whichever dataset is loaded.
- The attack successes in checks 11 and 14 are expected. They are the paper's flaws, which our ZK work is meant to fix.

## Reporting a problem

Give the portal and account, the steps you took, what you expected and what you saw. Add a screenshot and anything shown in the
browser console (F12 → Console).
