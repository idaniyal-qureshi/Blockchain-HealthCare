"""What the patient, clinician and hospital portals are allowed to see.

These roles use HealthSafe like any hospital system: who has access, for how long, and whether a request was granted. They never
receive *why* a request was decided (token, policy, consensus, integrity), nor anything about the ledger, validator nodes,
pseudonyms or the loaded dataset. Those stay in the admin portal, which gets the system layer's full output.

Every function here takes the system layer's (full) output and returns a reduced copy, so nothing extra reaches the browser.
"""
import time

import system as S

RESOURCE = {"EHR": "health record", "audit_logs": "access history"}
ACCESS = {"read": "view", "write": "edit"}


def _status(p):
    if p.get("revoked"): return "withdrawn"
    if p.get("expired"): return "expired"
    if p.get("governing"): return "active"
    return "replaced"                                             # a newer permission for the same hospital took over


def _perm(p, hospital=None):
    out = dict(role=p["role"], resource=p["resource"], access=p["access"], expires=p["expires"], status=_status(p))
    if hospital: out["hospital"] = hospital
    return out


# ------------------------------------------------------------------ patient
def patient(v):
    """The patient's vitals and who may see their record. No pseudonym, no token or policy internals."""
    hosp = []
    for h in S.HOSPITALS:
        shared = any(t["hospital"] == h and t["token_valid"] for t in v["token_holders"])
        cur = next((p for p in v["policies"] if p["entity"] == h and p["governing"]), None)
        hosp.append(dict(hospital=h, has_access=bool(shared and cur and h in cur["held_by"]),
                         current=_perm(cur) if cur else None))
    return dict(label=v["label"], hospitals=hosp,
                permissions=[_perm(p, p["entity"]) for p in v["policies"]][::-1],
                vitals=dict(hr=v["vitals"]["hr"], reference=v["vitals"]["truth"]))


OWN_EVENTS = {"grant": "You turned on sharing for a hospital", "policy_define": "You gave a hospital access",
              "policy_revoke": "You withdrew a hospital's access", "revoke": "You stopped sharing with every hospital"}


def patient_activity(s, pseud):
    """The patient's own changes, plus requests for their record (granted or declined), without saying which hospital or why."""
    rows = [dict(t=e["t"], kind="you", text=OWN_EVENTS[e["event"]])
            for e in s.patient_history(pseud)["events"] if e["event"] in OWN_EVENTS]
    for r in s.requests_for(pseud):
        what = f'{ACCESS[r["action"]]} your {RESOURCE[r["resource"]]}'
        text = {"granted": f"A hospital was allowed to {what}", "denied": f"A hospital asked to {what} and was declined",
                "unavailable": f"A hospital asked to {what}; the request could not be completed"}[r["outcome"]]
        rows.append(dict(t=r["t"], kind=r["outcome"], text=text))
    rows.sort(key=lambda x: x["t"], reverse=True)
    return dict(events=rows[:S.HISTORY_PAGE], total=len(rows))


# ------------------------------------------------------------------ clinician
def doctor_patients(rows):
    return [dict(id=p["pseud"], label=p["label"], n_records=p["n_records"], access=bool(p["token_valid"] and p["policy_held"]))
            for p in rows]


def doctor_result(out):
    """Granted with the record, or denied / unavailable: never which check decided it."""
    res = dict(status=S.outcome(out), patient=out["patient"], resource=out["resource"], action=out["action"])
    if out.get("record"):
        res["record"] = dict(hr=out["record"]["hr"], reference=out["record"]["truth"])
    return res


def request_row(r, with_staff=False):
    row = dict(t=r["t"], patient=r["patient"], resource=r["resource"], action=r["action"], outcome=r["outcome"])
    if with_staff: row["by"] = dict(username=(r.get("by") or {}).get("username"), name=(r.get("by") or {}).get("name"),
                                    role=(r.get("by") or {}).get("role"))
    return row


# ------------------------------------------------------------------ hospital
def hospital(v):
    pats = []
    for p in v["patients"]:
        sharing = "shared" if p["token_valid"] else "withdrawn" if p["token_held"] else "not shared"
        pats.append(dict(label=p["label"], n_records=p["n_records"], sharing=sharing, can_view=p["readable"],
                         permissions=[_perm(x) for x in p["policies"]][::-1]))
    st = v["stats"]
    return dict(hospital=v["hospital"], patients=pats, since=v["since"], per_staff=v["per_staff"],
                requests=[request_row(r, True) for r in v["requests"]], requests_shown=v["requests_shown"],
                stats=dict(sharing=st["consenting"], readable=st["readable"], patients=st["patients"], requests=st["requests"],
                           granted=st["granted"], denied=st["denied"]))


def context(ctx):
    """The shared header data, minus everything about the ledger, nodes and dataset."""
    return dict(dataset_id=ctx["dataset_id"], hospitals=ctx["hospitals"], hospital_names=ctx["hospital_names"], now=time.time())
