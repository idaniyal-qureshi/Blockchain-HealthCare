"""1. Fault-tolerant sensor ingestion (Sec. 4.1, 5.2, 5.3, 6.8, 6.9, Fig 2 "Sensor Pipeline")

* Signal model (Eq 2 / 14): `x_i = x*_i + δ + η`. Eq 14 and Eq 16 write the true value as `x*_i` with no time index, so each patient has one constant true value.
* Algorithm 1 exactly as written: sort, take `X[⌊n/2⌋]`, flag `|x_i − x̂| > ε`, warn if more than n/2 are faulty.
* Algorithm 2 with an estimated fault level η (the paper does not say how η is estimated: here a causal moving average of the fraction of readings Algorithm 1 flags).
  With n = 5 a per-time-step η could only be 0, 0.2, 0.4,..., which would make the median branch (`0.2 < η < 0.4`) unreachable; the moving average avoids that.
* Fig 2 pipeline: sensor authentication (HMAC tag per reading) → error detection (threshold + variance) → fault classification (type & severity)
  → adaptive correction (Algorithm 2) → "retry if failed" (retransmission, up to k times) → hand-over to the crypto layer. Groups still unreliable after k retries are quarantined.
* Benchmarked against no correction, mean, majority voting and a Kalman filter (Sec 6.9), over 5 runs.

* Edge data (Sec 3.2 steps 1-3): edge_records() turns the Fig 2 pipeline output into one record per patient per time step
  (corrected value + the 3-5 readings that arrived and passed authentication). encryption.py encrypts these on each patient's edge device;
  save_records_csv() keeps a plaintext reference copy so decrypted data can be checked.

Library part: generate_truth ... sensor_accuracy (used again by blockchain.py), edge_records, save_records_csv.  Experiment part: run().
"""
import os, time, hmac, struct, json
import numpy as np, pandas as pd, matplotlib.pyplot as plt
from common import CFG, SEED, rng, ci95, fmt, display, RESULTS

N_S = CFG["N_SENSORS"]
EDGE_PATIENTS = 10           # ASSUMPTION: patients whose full sensor stream (N_STEPS records each) is handed to the edge devices for encryption
EDGE_FAULT_RATE = 0.20       # ASSUMPTION: sensor fault rate of that data

def generate_truth(n_pat, rng):
    # Eq 14/16: x*_i has no time index -> one true value per patient.  ASSUMPTION: x*_i ~ U(60, 100) (heart-rate range)
    return rng.uniform(60, 100, size=n_pat)

def draw_readings(truth, fault_rate, rng):
    """Eq 2 / Eq 14: x_i = x* + delta_i + eta_i. ASSUMPTION: each reading is faulty independently with probability `fault_rate`.
    kind: 0 healthy, 1 missing, 2 spoof from a faulty/compromised sensor (valid MAC), 3 spoof injected by an outside attacker (A2, forged MAC)."""
    shape = truth.shape + (N_S,)
    x = truth[..., None] + rng.normal(0, CFG["SIGMA"], shape)
    faulty = rng.random(shape) < fault_rate
    missing = faulty & (rng.random(shape) < CFG["P_MISSING"])
    spoof = faulty & ~missing
    x = np.where(spoof, x + rng.choice(CFG["SPOOF"], size=shape) * rng.choice([-1, 1], size=shape), x)
    x = np.where(missing, np.nan, x)
    kind = np.zeros(shape, np.int8); kind[spoof] = 2
    kind[spoof & (rng.random(shape) < CFG["P_EXTERNAL_SPOOF"])] = 3; kind[missing] = 1
    return x, kind

def algorithm1(x, eps=CFG["EPS"]):
    """Algorithm 1 (adaptive median-based correction).
    Lines 1-2: X <- sort(x); x_hat <- X[floor(n/2)].  Missing readings never arrive, so n is the number received (upper middle if even).
    Lines 3-5: x_i faulty if |x_i - x_hat| > eps (a missing reading also counts as faulty).
    Lines 6-7: warning 'unreliable consensus' if #faulty > n/2 (n = number of sensors).  Returns (x_hat, faulty mask, warning)."""
    X = np.sort(x, axis=-1)                                           # NaN sorts to the end
    n_rx = (~np.isnan(x)).sum(-1)
    x_hat = np.take_along_axis(X, np.clip(n_rx // 2, 0, x.shape[-1] - 1)[..., None], -1)[..., 0]
    x_hat = np.where(n_rx == 0, np.nan, x_hat)
    faulty = np.isnan(x) | (np.abs(x - x_hat[..., None]) > eps)
    return x_hat, faulty, faulty.sum(-1) > x.shape[-1] / 2

def mode_rounded(x):
    """Mode of the readings rounded to the nearest integer (Algorithm 2 line 6-7, also the 'majority voting' baseline)."""
    r = np.round(x)
    counts = (r[..., :, None] == r[..., None, :]).sum(-1).astype(float); counts[np.isnan(r)] = -1
    return np.take_along_axis(r, counts.argmax(-1)[..., None], -1)[..., 0]

def fault_estimate(faulty, window=CFG["ETA_WINDOW"]):
    """Input eta of Algorithm 2.  ASSUMPTION (not given in the paper): per patient, the fraction of readings flagged by Algorithm 1
    over the last `window` time steps (causal moving average)."""
    f = faulty.mean(-1)
    c = np.concatenate([np.zeros((f.shape[0], 1)), np.cumsum(f, axis=1)], axis=1)
    t = np.arange(1, f.shape[1] + 1); lo = np.maximum(t - window, 0)
    return (c[:, t] - c[:, lo]) / (t - lo)

def algorithm2(x, eta):
    """Algorithm 2: mean if eta <= 0.2; median if 0.2 < eta < 0.4; otherwise mode of the rounded readings."""
    return np.where(eta <= 0.2, np.nanmean(x, -1), np.where(eta < 0.4, np.nanmedian(x, -1), mode_rounded(x)))

def agg_kalman(x, q=1e-4, r=0.08, gate=5.0):
    """ASSUMPTION: the paper benchmarks a 'Kalman filter' without details. Scalar filter over time on the per-step median
    (measurement variance ~ (1.2533 sigma)^2 / 5), random-walk process noise q, innovation gating at 5 sigma."""
    z = algorithm1(x)[0]; P_, T = z.shape
    xk = np.where(np.isnan(z[:, 0]), 80.0, z[:, 0]); pk = np.full(P_, r); est = np.empty_like(z)
    for t in range(T):
        pk = pk + q; innov = z[:, t] - xk; S = pk + r
        ok = ~np.isnan(innov) & (np.abs(innov) <= gate * np.sqrt(S)); K = pk / S
        xk = np.where(ok, xk + K * innov, xk); pk = np.where(ok, (1 - K) * pk, pk); est[:, t] = xk
    return est

def sensor_auth(x, kind, pat, stp, attempt, keys):
    """Fig 2 'Sensor Authentication (token or signature check)'. Each sensor holds a key and tags every reading with
    HMAC-SHA256(key, patient|step|attempt|sensor|value) truncated to 8 bytes; the gateway recomputes the tag.
    Readings injected by an outside attacker (kind 3) carry a forged tag. Missing readings never arrive."""
    xf, kf = x.reshape(-1, N_S), kind.reshape(-1, N_S); pf, sf = np.ravel(pat), np.ravel(stp)
    ok = np.zeros(xf.shape, bool)
    for r in range(xf.shape[0]):
        p, t = int(pf[r]), int(sf[r]); kp = keys[p]
        for j in range(N_S):
            k = kf[r, j]
            if k == 1: continue
            msg = struct.pack(">IIHHd", p, t, attempt, j, xf[r, j])
            tag = os.urandom(8) if k == 3 else hmac.digest(kp[j], msg, "sha256")[:8]          # sensor side
            ok[r, j] = hmac.compare_digest(hmac.digest(kp[j], msg, "sha256")[:8], tag)      # gateway side
    return ok.reshape(x.shape)

FAULT_CLASSES = ["ok", "missing", "unauthenticated", "minor deviation", "severe deviation"]

def fig2_pipeline(truth, fault_rate, rng, keys, authenticate=True):
    """Fig 2 sensor pipeline for a (patients x steps) truth matrix. Returns corrected values (NaN = quarantined), retransmissions,
    fault-class counts and detection counts against the injected ground truth."""
    P, T = truth.shape
    pat = np.repeat(np.arange(P)[:, None], T, 1); stp = np.repeat(np.arange(T)[None, :], P, 0)
    x, kind = draw_readings(truth, fault_rate, rng)
    auth_ok = sensor_auth(x, kind, pat, stp, 0, keys) if authenticate else ~np.isnan(x)
    out, retx, pending = np.full((P, T), np.nan), np.zeros((P, T), int), np.ones((P, T), bool)
    cls, det, eta = np.zeros(5, int), dict(tp=0, fp=0, fn=0), None
    for attempt in range(CFG["RETRY_K"] + 1):
        sel = pending.copy(); idx = np.argwhere(sel)
        xs, ks, ok = x[sel], kind[sel], auth_ok[sel]
        xv = np.where(ok, xs, np.nan)                                   # unauthenticated readings are discarded
        x_hat, flagged, unreliable = algorithm1(xv)                     # error detection: threshold (Algorithm 1)
        error = flagged.any(-1) | (np.nanstd(xv, -1) > CFG["EPS"])     # error detection: variance
        dev = np.abs(xs - x_hat[:, None])                               # fault classification: type & severity
        code = np.where(np.isnan(xs), 1, np.where(~ok, 2, np.where(dev > CFG["SEVERE_DEV"], 4, np.where(dev > CFG["EPS"], 3, 0))))
        cls += np.bincount(code.ravel(), minlength=5)
        inj = ks != 0
        det["tp"] += int((flagged & inj).sum()); det["fp"] += int((flagged & ~inj).sum()); det["fn"] += int((~flagged & inj).sum())
        if eta is None:
            fl = np.zeros((P, T, N_S), bool); fl[sel] = flagged; eta = fault_estimate(fl)
        # Sensor correction (adaptive strategy): Algorithm 2 over the readings not classified as faulty (ASSUMPTION: the
        # classification step feeds the correction step, as the Fig 2 arrows show). Clean groups (no error) take the plain mean.
        est = algorithm2(np.where(flagged, np.nan, xv), eta[sel])
        val = np.where(error, est, np.nanmean(xv, -1))
        good = idx[~unreliable]; out[good[:, 0], good[:, 1]] = val[~unreliable]
        pending = np.zeros((P, T), bool); bad = idx[unreliable]; pending[bad[:, 0], bad[:, 1]] = True
        if attempt == CFG["RETRY_K"] or not pending.any(): break
        retx[pending] += 1                                              # 'retry if failed': the gateway requests a retransmission
        xn, kn = draw_readings(truth[pending], fault_rate, rng)
        x[pending], kind[pending] = xn, kn
        auth_ok[pending] = sensor_auth(xn, kn, pat[pending], stp[pending], attempt + 1, keys) if authenticate else ~np.isnan(xn)
    return dict(est=out, retx=retx, quarantined=pending, cls=cls, det=det, readings=np.where(auth_ok, x, np.nan))

def sensor_accuracy(est, truth):                                       # Eq 16 (quarantined/missing outputs count as wrong)
    return float(np.mean(np.abs(est - truth) <= CFG["ACC_TOL"]) * 100)

def edge_records(n_patients=EDGE_PATIENTS, fault_rate=EDGE_FAULT_RATE, n_steps=CFG["N_STEPS"], seed=SEED + 7):
    """Sensor output that each patient's edge device encrypts (Sec 3.2 steps 1-3).
    Runs the Fig 2 pipeline and returns {patient_id: [record, ...]}, one record per time step:
        pid, step, t_s (seconds since start, 1 reading every 3 s), hr (corrected value, None if quarantined),
        raw (the readings that arrived and passed authentication, usually 3-5 of the 5 sensors)."""
    r = np.random.default_rng(seed)
    truth = np.repeat(generate_truth(n_patients, r)[:, None], n_steps, axis=1)
    keys = [[os.urandom(16) for _ in range(N_S)] for _ in range(n_patients)]
    pipe = fig2_pipeline(truth, fault_rate, r, keys)
    est, readings = pipe["est"], pipe["readings"]
    out = {}
    for p in range(n_patients):
        out[p] = [dict(pid=p, step=t, t_s=t * CFG["READ_INTERVAL_S"],
                       hr=None if np.isnan(est[p, t]) else round(float(est[p, t]), 2),
                       raw=[round(float(v), 2) for v in readings[p, t] if not np.isnan(v)])
                  for t in range(n_steps)]
    return out

def save_records_csv(records, path="sensor_records.csv"):
    """Plaintext reference copy of the edge records (one row per patient per time step)."""
    rows = [dict(rec, raw=json.dumps(rec["raw"])) for recs in records.values() for rec in recs]
    pd.DataFrame(rows).to_csv(path, index=False)
    return path


def run():
    """Sensor experiments (Eq 16, Figs 10-11). Fills RESULTS and returns PIPE (retransmission table, used by the Eq 13 energy model)."""
    truth = generate_truth(CFG["N_PATIENTS"], rng)
    TRUTH = np.repeat(truth[:, None], CFG["N_STEPS"], axis=1)
    SENSOR_KEYS = [[os.urandom(16) for _ in range(N_S)] for _ in range(CFG["N_PATIENTS"])]
    rows, flag_rows, cls_rows, pipe_rows = [], [], [], []
    t_start = time.time()
    for run in range(CFG["N_RUNS"]):
        r_rng = np.random.default_rng(SEED + 100 + run)
        for fr in CFG["FAULT_RATES"]:
            x, kind = draw_readings(TRUTH, fr, r_rng)
            xh, fl, unrel = algorithm1(x)
            ests = {"No correction": x[..., 0], "Mean smoothing": np.nanmean(x, -1), "Majority voting": mode_rounded(x),
                    "3-of-5 Median (Alg. 1)": xh, "Kalman filter": agg_kalman(x), "Adaptive (Alg. 2)": algorithm2(x, fault_estimate(fl))}
            pipe = fig2_pipeline(TRUTH, fr, r_rng, SENSOR_KEYS)
            ests["Full Fig 2 pipeline"] = pipe["est"]
            for m, e in ests.items(): rows.append(dict(run=run, fault_rate=int(round(fr * 100)), method=m, accuracy=sensor_accuracy(e, TRUTH)))
            pipe_rows.append(dict(run=run, fault_rate=int(round(fr * 100)), retx_per_group=pipe["retx"].mean(),
                                  quarantined_pct=pipe["quarantined"].mean() * 100,
                                  baseline_retx_per_group=fl.any(-1).mean()))   # no correction layer: every anomalous group is re-sent
            if run == 0:
                wrong = np.abs(xh - TRUTH) > CFG["ACC_TOL"]; d = pipe["det"]
                flag_rows.append(dict(fault_rate=int(round(fr * 100)), flagged_unreliable_pct=unrel.mean() * 100, wrong_pct=wrong.mean() * 100,
                                      wrong_that_were_flagged_pct=(unrel & wrong).sum() / max(wrong.sum(), 1) * 100,
                                      detection_precision_pct=100 * d["tp"] / max(d["tp"] + d["fp"], 1),
                                      detection_recall_pct=100 * d["tp"] / max(d["tp"] + d["fn"], 1)))
                cls_rows.append(dict(fault_rate=int(round(fr * 100)), **{c: int(v) for c, v in zip(FAULT_CLASSES, pipe["cls"])}))
    print(f"Sensor experiments: {CFG['N_RUNS']} runs x {len(CFG['FAULT_RATES'])} fault rates in {time.time() - t_start:.0f} s")

    acc = pd.DataFrame(rows); g = acc.groupby(["method", "fault_rate"]).accuracy
    sensor_mean, sensor_ci = g.mean().unstack(), g.agg(ci95).unstack()
    order = ["No correction", "Mean smoothing", "Majority voting", "3-of-5 Median (Alg. 1)", "Kalman filter", "Adaptive (Alg. 2)", "Full Fig 2 pipeline"]
    sensor_mean, sensor_ci = sensor_mean.loc[order], sensor_ci.loc[order]
    print("Sensor correction accuracy, % within ±1 (mean ± 95% CI over runs)  [Eq 16, Figs 10-11]")
    display(pd.DataFrame({c: [fmt(sensor_mean.loc[m, c], sensor_ci.loc[m, c]) for m in order] for c in sensor_mean.columns}, index=order))
    print("Algorithm 1 warnings and error-detection quality (run 0):"); display(pd.DataFrame(flag_rows).round(2).set_index("fault_rate"))
    print("Fault classification counts, Fig 2 pipeline (run 0, all attempts):"); display(pd.DataFrame(cls_rows).set_index("fault_rate"))
    PIPE = pd.DataFrame(pipe_rows).groupby("fault_rate").mean().drop(columns="run")
    print("Retransmissions per reading group and quarantined groups (mean over runs):"); display(PIPE.round(4))
    for fr in sensor_mean.columns:
        RESULTS[f"median_{fr}"], RESULTS[f"kalman_{fr}"] = sensor_mean.loc["3-of-5 Median (Alg. 1)", fr], sensor_mean.loc["Kalman filter", fr]
        RESULTS[f"mean_{fr}"], RESULTS[f"none_{fr}"] = sensor_mean.loc["Mean smoothing", fr], sensor_mean.loc["No correction", fr]

    # ---------------- Figs 10-11 ----------------
    rates = list(sensor_mean.columns)
    fig, ax = plt.subplots(figsize=(7, 4))                                  # Fig 10
    ax.errorbar(rates, sensor_mean.loc["3-of-5 Median (Alg. 1)"], yerr=sensor_ci.loc["3-of-5 Median (Alg. 1)"], marker="o", capsize=3, label="3-of-5 median (Alg. 1)")
    ax.errorbar(rates, sensor_mean.loc["Full Fig 2 pipeline"], yerr=sensor_ci.loc["Full Fig 2 pipeline"], marker="s", capsize=3, label="Full Fig 2 pipeline")
    ax.set_xlabel("Fault rate (%)"); ax.set_ylabel("Accuracy (%)"); ax.grid(alpha=.3); ax.legend(); ax.set_title("Sensor accuracy vs injected fault rate (cf. Fig 10)")
    plt.savefig("fig10_sensor_accuracy.png", bbox_inches="tight"); plt.show()
    fig, ax = plt.subplots(figsize=(9, 4))                                  # Fig 11
    w = 0.8 / len(order); xs_ = np.arange(len(rates))
    for i, m in enumerate(order): ax.bar(xs_ + i * w, sensor_mean.loc[m], w, yerr=sensor_ci.loc[m], capsize=2, label=m)
    ax.set_xticks(xs_ + 0.4 - w / 2); ax.set_xticklabels([f"{r}%" for r in rates]); ax.set_ylabel("Accuracy (%)"); ax.set_xlabel("Fault rate")
    ax.legend(fontsize=7, bbox_to_anchor=(1.01, 1), loc="upper left"); ax.grid(alpha=.3, axis="y"); ax.set_title("Sensor correction accuracy vs fault rate (cf. Fig 11)")
    plt.savefig("fig11_sensor_methods.png", bbox_inches="tight"); plt.show()
    return dict(PIPE=PIPE, sensor_mean=sensor_mean, sensor_ci=sensor_ci)


if __name__ == "__main__":
    run()
