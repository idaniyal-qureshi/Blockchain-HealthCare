"""Real-data experiment: the base sensor-correction methods on WildPPG heart rate (4 real redundant sensors, ECG answer key).

The base experiment (code/v2_components/sensors.py, Eq 14/16, Figs 10-11) invents a true value x*, adds N(0, 0.5) noise and injects
missing readings and ±15/±25 spoofs into 5 simulated sensors. Here nothing is simulated or injected: the readings are real.

* Data: WildPPG (Meier, Demirel & Holz, NeurIPS 2024 Datasets and Benchmarks; CC BY-NC-SA 4.0). Each participant wears 4 PPG
  devices (sternum, head, wrist, ankle) for a whole day. `wildppg.extract_windows` turns each 8-s window into one heart rate per PPG
  location (= 4 redundant sensors) plus the heart rate of the sternum device's ECG (= answer key x*) and per-location motion.
* Methods: the base functions are imported and called unchanged, exactly as `sensors.run()` calls them, on x of shape
  (1 patient, T windows, 4 sensors): single sensors (the base "No correction" uses sensor 0; here each of the 4 is shown), mean,
  majority voting (`mode_rounded`), Algorithm 1 median, Kalman filter, Algorithm 2 with `fault_estimate`, and the Fig 2 pipeline.
* Fig 2 pipeline: `fig2_single_attempt` rebuilds attempt 0 of `sensors.fig2_pipeline` from the base functions only, without HMAC
  authentication (genuine recordings, no attacker) and without retransmission (recorded data cannot be re-measured).
  `sensors.fig2_pipeline` itself cannot be used: it draws its own simulated readings from a truth matrix.
* Metrics: Eq 16 accuracy (% within ±1 bpm, CFG["ACC_TOL"]; NaN/quarantined outputs count as wrong, like `sensors.sensor_accuracy`),
  % within ±5 bpm, MAE and RMSE (over windows with an estimate), coverage; overall and by activity tercile (motion).
No base file is edited.

Run (from anywhere):
    python code/extensions/data_layer/run_wildppg.py                                 # all .mat files from wildppg.list_participants()
    python code/extensions/data_layer/run_wildppg.py --participant <path/to/WildPPG_Part_an0.mat>
    python code/extensions/data_layer/run_wildppg.py --from-csv code/extensions/data_layer/data/wildppg/WildPPG_Part_an0_ppg_g_w8_charlton.csv
Outputs in --out (default code/extensions/data_layer/output/wildppg): <participant>/windows.csv, metrics.csv, fig_*.png;
pooled_metrics.csv (if >1 participant); summary.md.
"""
import sys, re, pathlib, argparse, warnings
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "v2_components")); sys.path.insert(0, str(HERE))
import matplotlib
matplotlib.use("Agg")
warnings.filterwarnings("ignore", message=".*non-interactive.*")
import numpy as np, pandas as pd, matplotlib.pyplot as plt
import sensors, wildppg
from common import CFG

LOCATIONS = wildppg.LOCATIONS
METHOD_ORDER = ["Sternum PPG only", "Head PPG only", "Wrist PPG only", "Ankle PPG only", "Mean smoothing", "Majority voting",
                "Median (Alg. 1)", "Kalman filter", "Adaptive (Alg. 2)", "Fig 2 pipeline (single attempt)"]
ACTIVITY = ["calm", "moderate", "active"]
METRICS = ["n", "MAE", "RMSE", "within_1_pct", "within_5_pct", "coverage_pct"]
WIDE_TOL = 5.0                                                         # secondary tolerance (bpm), more realistic for PPG
COLUMNS = ["window", "t_s", "ecg_hr", *LOCATIONS, *[f"motion_{loc}" for loc in LOCATIONS]]
DEFAULT_OUT = HERE / "output" / "wildppg"
# Sample ranges the dataset's own `notes` (in the participant .mat) say to exclude: 0-based, inclusive, at FS = 128 Hz (the notes give
# MATLAB 1-based inclusive indices; 1 is subtracted). The an0 note names the ankle device but says "data from the wrist", so the device is
# ambiguous; for one consistent rule the overlapping windows are dropped for ALL sensors and the ECG, for every participant.
#   an0: ankle interruption, 15 s   (MATLAB 284544-286401)
#   k2s: wrist interruption, 53 min (MATLAB 3786940-4194811)
#   l38: wrist interruption, 27 min (MATLAB 4337573-4545544)
# The other 13 participants' notes contain no sample ranges (checked for all 16 on the share).
EXCLUDE = {"an0": [(284543, 286400)], "k2s": [(3786939, 4194810)], "l38": [(4337572, 4545543)]}
# Participants whose notes say "ECG recordings of this participant are noisy." Their ECG answer key covers only 28-34 % of windows
# (Pan-Tompkins + strict rule; no other NeuroKit2 detector reached 50 %), so they are left out of the main pooled result by default
# (--include-noisy-ecg puts them back, e.g. as a sensitivity check).
NOISY_ECG = {"fex", "kjd", "p5d"}
slug = lambda m: "est_" + re.sub(r"[^a-z0-9]+", "_", m.lower()).strip("_")

def readings_matrix(df):
    """Per-window HR of the 4 PPG locations as the base layout x[patient, step, sensor]: shape (1, T, 4), LOCATIONS order."""
    return df[list(LOCATIONS)].to_numpy(float)[None]

def fig2_single_attempt(x, eps=CFG["EPS"]):
    """Attempt 0 of `sensors.fig2_pipeline`, line by line, for RECORDED readings x (patients, steps, sensors; NaN = missing).
    Error detection: Algorithm 1 flags (threshold) or nanstd > eps (variance). Groups with an error: Algorithm 2 over the non-flagged
    readings, with eta = `fault_estimate` of the attempt-0 flags; groups without an error: plain mean. Unreliable groups (Algorithm 1:
    more than n/2 readings flagged, missing included) are quarantined (NaN).
    Differences vs the base: no HMAC sensor authentication (the readings are genuine recordings, there is no attacker; missing readings
    play the role of non-arriving ones) and no retransmission (recorded data cannot be re-measured), so unreliable groups are
    quarantined at once instead of being retried up to k = CFG["RETRY_K"] times. Fault classification only feeds counters in the base
    and does not change the output, so it is omitted."""
    xv = np.asarray(x, float)
    x_hat, flagged, unreliable = sensors.algorithm1(xv, eps)
    error = flagged.any(-1) | (np.nanstd(xv, -1) > eps)
    eta = sensors.fault_estimate(flagged)
    est = sensors.algorithm2(np.where(flagged, np.nan, xv), eta)
    val = np.where(error, est, np.nanmean(xv, -1))
    return dict(est=np.where(unreliable, np.nan, val), quarantined=unreliable, flagged=flagged, error=error, eta=eta, x_hat=x_hat)

def run_methods(df):
    """name -> per-window estimate (length T) for every METHOD_ORDER entry, using the base functions as `sensors.run()` does."""
    x = readings_matrix(df)
    xh, fl, _ = sensors.algorithm1(x)
    ests = {f"{loc.capitalize()} PPG only": x[..., i] for i, loc in enumerate(LOCATIONS)}
    ests.update({"Mean smoothing": np.nanmean(x, -1), "Majority voting": sensors.mode_rounded(x), "Median (Alg. 1)": xh,
                 "Kalman filter": sensors.agg_kalman(x), "Adaptive (Alg. 2)": sensors.algorithm2(x, sensors.fault_estimate(fl)),
                 "Fig 2 pipeline (single attempt)": fig2_single_attempt(x)["est"]})
    return {m: np.asarray(ests[m], float)[0] for m in METHOD_ORDER}

def metrics(est, truth):
    """Metrics over windows with a finite truth. within_*: Eq 16 rule (NaN estimate = wrong); MAE/RMSE: windows with an estimate."""
    est, truth = np.asarray(est, float), np.asarray(truth, float)
    m = np.isfinite(truth); n = int(m.sum()); e, t = est[m], truth[m]
    ok = np.isfinite(e); err = np.abs(e[ok] - t[ok])
    pct = lambda tol: float(np.mean(np.abs(e - t) <= tol) * 100) if n else np.nan
    return dict(n=n, MAE=float(err.mean()) if ok.any() else np.nan, RMSE=float(np.sqrt((err ** 2).mean())) if ok.any() else np.nan,
                within_1_pct=pct(CFG["ACC_TOL"]), within_5_pct=pct(WIDE_TOL), coverage_pct=float(ok.mean() * 100) if n else np.nan)

def activity_levels(df):
    """'calm' / 'moderate' / 'active' = terciles of the mean motion over the 4 locations (NaN motion -> NaN level)."""
    mot = df[[f"motion_{loc}" for loc in LOCATIONS]].to_numpy(float)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning); mean = pd.Series(np.nanmean(mot, 1), index=df.index)
    lev = pd.Series(np.nan, index=df.index, dtype=object); ok = mean.notna()
    if ok.sum() >= 3: lev[ok] = pd.qcut(mean[ok].rank(method="first"), 3, labels=ACTIVITY).astype(object)   # rank: ties cannot break the bins
    return pd.Series(pd.Categorical(lev, categories=ACTIVITY), index=df.index, name="activity")

def excluded_windows(pid, exclude=None):
    """Window indices overlapping any excluded sample range of participant `pid` (window k covers samples k*L .. (k+1)*L - 1)."""
    L = wildppg.FS * wildppg.WIN_S
    return sorted({k for s0, s1 in (EXCLUDE if exclude is None else exclude).get(pid, []) for k in range(s0 // L, s1 // L + 1)})

def _pid(name):
    """'WildPPG_Part_an0' -> 'an0'."""
    return re.sub(r"^WildPPG_Part_", "", name)

def apply_exclusions(df, name, exclude=None):
    """Drop the windows of EXCLUDE (matched on the `window` column) before anything is computed. Returns (kept df, dropped windows)."""
    bad = excluded_windows(_pid(name), exclude)
    drop = df["window"].isin(bad)
    return df[~drop].reset_index(drop=True), sorted(df.loc[drop, "window"].astype(int).tolist())

def _evaluate(ests, truth, levels):
    rows = []
    for m in METHOD_ORDER:
        for a in ["all", *ACTIVITY]:
            sel = np.ones(len(truth), bool) if a == "all" else (np.asarray(levels.astype(object)) == a)
            rows.append(dict(method=m, activity=a, **metrics(np.asarray(ests[m])[sel], np.asarray(truth, float)[sel])))
    return pd.DataFrame(rows).set_index(["method", "activity"])[METRICS]

def evaluate(df):
    """Rows: (method, activity in all/calm/moderate/active); columns: METRICS."""
    return _evaluate(run_methods(df), df["ecg_hr"].to_numpy(float), activity_levels(df))

# ---------------- figures ----------------
def _fig_accuracy(res, path, title):
    a = res.xs("all", level="activity").loc[METHOD_ORDER]; y = np.arange(len(METHOD_ORDER))
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.barh(y - 0.2, a["within_1_pct"], 0.4, label="within ±1 bpm (Eq 16)"); ax.barh(y + 0.2, a["within_5_pct"], 0.4, label="within ±5 bpm")
    for yy, v1, v5 in zip(y, a["within_1_pct"], a["within_5_pct"]):
        ax.text(v1 + 0.5, yy - 0.2, f"{v1:.1f}", va="center", fontsize=7); ax.text(v5 + 0.5, yy + 0.2, f"{v5:.1f}", va="center", fontsize=7)
    ax.set_yticks(y); ax.set_yticklabels(METHOD_ORDER); ax.invert_yaxis(); ax.set_xlim(0, 105); ax.set_xlabel("% of windows (NaN output = wrong)")
    ax.grid(alpha=.3, axis="x"); ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=2, fontsize=8); ax.set_title(title)
    fig.savefig(path, bbox_inches="tight"); plt.close(fig)

def _fig_mae_activity(res, path, title):
    fig, ax = plt.subplots(figsize=(10, 4.5)); xs = np.arange(len(METHOD_ORDER)); w = 0.2
    for i, a in enumerate(["all", *ACTIVITY]):
        ax.bar(xs + (i - 1.5) * w, res.xs(a, level="activity").loc[METHOD_ORDER, "MAE"], w, label=a)
    ax.set_xticks(xs); ax.set_xticklabels(METHOD_ORDER, rotation=35, ha="right", fontsize=8); ax.set_ylabel("MAE vs ECG (bpm)")
    ax.grid(alpha=.3, axis="y"); ax.legend(title="activity (motion tercile)", fontsize=8); ax.set_title(title)
    fig.savefig(path, bbox_inches="tight"); plt.close(fig)

def _fig_timeseries(df, ests, path, title):
    """ECG HR vs the Algorithm 1 median of the 4 PPG sensors, 1-minute rolling medians (time-based), the 4 sensors faint."""
    idx = pd.to_timedelta(df["t_s"].to_numpy(float), unit="s")
    roll = lambda v: pd.Series(np.asarray(v, float), index=idx).rolling("60s", min_periods=1).median().to_numpy()
    h = df["t_s"].to_numpy(float) / 3600
    fig, ax = plt.subplots(figsize=(14, 4.5))
    for loc in LOCATIONS: ax.plot(h, roll(df[loc]), lw=0.4, alpha=0.35, label=f"{loc} PPG")
    ax.plot(h, roll(df["ecg_hr"]), lw=0.7, color="k", label="ECG (answer key)")
    ax.plot(h, roll(ests["Median (Alg. 1)"]), lw=0.7, color="tab:red", label="Median of 4 (Alg. 1)")
    ax.set_xlabel("time since start (h)"); ax.set_ylabel("heart rate (bpm, 1-min rolling median)"); ax.grid(alpha=.3)
    ax.legend(fontsize=7, ncol=6, loc="upper right"); ax.set_title(title)
    fig.savefig(path, bbox_inches="tight"); plt.close(fig)

def _fig_errors(df, ests, path, title):
    t = df["ecg_hr"].to_numpy(float)
    data = [np.abs(ests[m] - t)[np.isfinite(ests[m] - t)] for m in METHOD_ORDER]
    fig, ax = plt.subplots(figsize=(10, 4.5))
    ax.boxplot([d if len(d) else [np.nan] for d in data], showfliers=False)
    ax.set_xticks(range(1, len(METHOD_ORDER) + 1)); ax.set_xticklabels(METHOD_ORDER, rotation=35, ha="right", fontsize=8)
    ax.axhline(CFG["ACC_TOL"], color="tab:red", lw=0.8, ls="--", label="±1 bpm (Eq 16)"); ax.axhline(WIDE_TOL, color="tab:orange", lw=0.8, ls="--", label="±5 bpm")
    ax.set_ylabel("|estimate - ECG| (bpm), outliers hidden"); ax.grid(alpha=.3, axis="y"); ax.legend(fontsize=8); ax.set_title(title)
    fig.savefig(path, bbox_inches="tight"); plt.close(fig)

# ---------------- summary ----------------
def _md_table(res, activity="all"):
    a = res.xs(activity, level="activity").loc[METHOD_ORDER]
    lines = ["| Method | n | within ±1 (%) | within ±5 (%) | MAE | RMSE | coverage (%) |", "|---|---:|---:|---:|---:|---:|---:|"]
    lines += [f"| {m} | {int(r.n)} | {r.within_1_pct:.1f} | {r.within_5_pct:.1f} | {r.MAE:.2f} | {r.RMSE:.2f} | {r.coverage_pct:.1f} |" for m, r in a.iterrows()]
    return "\n".join(lines)

def _md_activity(res, col="within_1_pct", nd=1):
    lines = ["| Method | all | calm | moderate | active |", "|---|---:|---:|---:|---:|"]
    lines += [f"| {m} | " + " | ".join(f"{res.loc[(m, a), col]:.{nd}f}" for a in ["all", *ACTIVITY]) + " |" for m in METHOD_ORDER]
    return "\n".join(lines)

def write_summary(out, parts, pooled, skipped=()):
    """parts: list of (name, windows DataFrame, metrics DataFrame); pooled: metrics DataFrame or None; skipped: participant names left
    out as noisy-ECG (NOISY_ECG)."""
    main_res = pooled if pooled is not None else parts[0][2]
    a = main_res.xs("all", level="activity")
    w1 = lambda m: f"{a.loc[m, 'within_1_pct']:.1f} %"
    L = ["# Real-data experiment: base sensor correction on WildPPG heart rate", "",
         "## Dataset", "",
         "WildPPG: M. Meier, B. U. Demirel, C. Holz, *WildPPG: A Real-World PPG Dataset of Long Continuous Recordings*, "
         "NeurIPS 2024 Datasets and Benchmarks Track (ETH Zürich). Licence: CC BY-NC-SA 4.0 (non-commercial, share-alike, attribution). "
         "The raw .mat files and the extracted window CSVs stay local (`data/` is gitignored).", "",
         "Each participant wears 4 PPG devices (sternum, head, wrist, ankle) during everyday life. Per 8-s window, `wildppg.py` extracts "
         f"one heart rate from the green PPG of each device (NeuroKit2 `{wildppg.PPG_METHOD}` beat detector, the same for all four devices) "
         "and one from the sternum device's ECG (answer key x*), "
         "plus the motion level of each device (std of acceleration magnitude).", "",
         "Exclusions: sample ranges the participant file's `notes` mark as invalid (an0: 15-s ankle gap; k2s: 53-min and l38: 27-min wrist "
         "gaps) are dropped before evaluation, for all 4 PPG sensors and the ECG, one rule for all because the an0 note is ambiguous about "
         "the device (`EXCLUDE` in run_wildppg.py). Dropped windows are removed, not set to missing, so they neither count as wrong nor "
         "raise the Algorithm 2 fault estimate.", ""]
    if skipped:
        L += [f"Left out: {', '.join(f'`{s}`' for s in skipped)}. The dataset notes say \"ECG recordings of this participant are noisy\", "
              "and the extracted ECG answer key covers only 28-34 % of their windows (`NOISY_ECG`; rerun with --include-noisy-ecg to add "
              "them).", ""]
    for name, w, _ in parts:
        t = w["t_s"].to_numpy(float); n_truth = int(np.isfinite(w["ecg_hr"]).sum())
        miss = ", ".join(f"{loc} {np.isnan(w[loc].to_numpy(float)).mean() * 100:.1f} %" for loc in LOCATIONS)
        ex = w.attrs.get("excluded", [])
        exs = f"{len(ex)} windows excluded per the dataset notes (window {', '.join(map(str, ex))}), " if ex else "no windows excluded, "
        L.append(f"- `{name}`: {exs}{len(w)} windows evaluated over {(np.nanmax(t) - np.nanmin(t)) / 3600:.1f} h; ECG HR available in {n_truth} "
                 f"({n_truth / max(len(w), 1) * 100:.1f} %); missing PPG HR: {miss}.")
    L += ["", "## What is real and what is simulated now", "",
          "| | Base experiment (`sensors.run()`) | This experiment |", "|---|---|---|",
          "| True value x* | invented, U(60, 100), constant per patient | ECG heart rate per 8-s window (varies over the day) |",
          "| Sensors | 5 simulated | 4 real PPG devices on different body sites |",
          "| Noise | N(0, 0.5) | real: motion artefacts, poor contact, peak-detection errors |",
          "| Faults | injected missing / ±15 / ±25 spoofs at 5-30 % | real only, none injected; missing = no HR extracted |",
          "| Attacker / HMAC | outside attacker forges readings | none (genuine recordings): authentication step skipped |",
          "| Retransmission | unreliable groups re-measured up to k = 3 times | impossible on recorded data: quarantined at once |",
          "| Methods, ε, η window, Kalman q/r/gate, Eq 16 | base code | the same base functions, unchanged |", "",
          "## Methods", "",
          "| Method | Base function (called unchanged) |", "|---|---|",
          "| Sternum / Head / Wrist / Ankle PPG only | one sensor column (the base's \"No correction\" = sensor 0) |",
          "| Mean smoothing | `np.nanmean` across sensors |", "| Majority voting | `sensors.mode_rounded` |",
          "| Median (Alg. 1) | `sensors.algorithm1(x)[0]` (with 4 readings: the upper middle one, X[⌊n/2⌋]) |",
          "| Kalman filter | `sensors.agg_kalman(x)` |", "| Adaptive (Alg. 2) | `sensors.algorithm2(x, sensors.fault_estimate(flags))` |",
          "| Fig 2 pipeline (single attempt) | `fig2_single_attempt`: attempt 0 of `sensors.fig2_pipeline` built from `algorithm1`, `fault_estimate`, "
          "`algorithm2`, nanstd > ε; no HMAC, no retry; unreliable windows quarantined (NaN, counted wrong) |", "",
          "Accuracy (Eq 16) = % of windows with an ECG answer whose estimate is within ±1 bpm (CFG[\"ACC_TOL\"]); NaN/quarantined estimates "
          "count as wrong, as in `sensors.sensor_accuracy`. MAE/RMSE are over windows with an estimate; coverage = % of those windows "
          "with an estimate. Activity = tercile of the mean motion over the 4 devices (per participant).", ""]
    for name, _, res in parts:
        L += [f"## Results: `{name}`", "", _md_table(res), "", "Within ±1 bpm (%) by activity:", "", _md_activity(res), "",
              "MAE (bpm) by activity:", "", _md_activity(res, "MAE", 2), "",
              f"Figures: `{name}/fig_accuracy.png`, `{name}/fig_mae_by_activity.png`, `{name}/fig_timeseries.png`, `{name}/fig_errors.png`.", ""]
    if pooled is not None:
        L += [f"## Pooled over {len(parts)} participants", "", _md_table(pooled), "", "Within ±1 bpm (%) by activity:", "", _md_activity(pooled), ""]
    singles = a.loc[METHOD_ORDER[:4], "within_1_pct"]
    L += ["## Comparison with the paper and the base simulation", "",
          "| Method | Paper | Base simulation (5 sensors, injected faults 5/10/15/20/30 %) | WildPPG (real, ±1 bpm) |", "|---|---|---|---|",
          f"| Median (Alg. 1) | 96-100 % within ±1 (Fig 10) | 99.8 / 99.4 / 98.8 / 97.5 / 93.9 % | {w1('Median (Alg. 1)')} |",
          f"| Kalman filter | 92.1-96.7 % (Sec 6.9) | see base Fig 11 | {w1('Kalman filter')} |",
          f"| Fig 2 pipeline | - | 99.6-99.99 % (with retransmission) | {w1('Fig 2 pipeline (single attempt)')} (single attempt) |",
          f"| Best single sensor | - | - | {singles.max():.1f} % ({singles.idxmax()}) |", "",
          "## Caveats", "",
          "- 4 sensors, not 5: Algorithm 1 takes the upper middle of 4 and calls a window unreliable when 3 or more of the 4 are flagged or missing.",
          f"- Heart rate is extracted by NeuroKit2 from raw PPG/ECG (PPG: `{wildppg.PPG_METHOD}` detector, chosen over the default Elgendi "
          "detector because it did better or equal at every location on an0, notably the ankle), so the errors include beat-detection "
          "errors, not only sensor faults. The ECG answer key was used only to compare detectors, never to choose a reading per window.",
          "- The ECG answer key is ECG-derived HR from our own extraction; it approximates, but is not identical to, the authors' cleaned reference.",
          "- ±1 bpm (Eq 16) is very strict for PPG: even good wrist PPG is usually judged at ±5 bpm or by MAE, so both are reported.",
          "- The Kalman filter (q, r, 5σ gate) and ε = 1.5 were tuned by the base for the simulated σ = 0.5 noise and a constant x*; real HR "
          "changes over time and PPG noise is far larger, so these parameters are not tuned for this data. They are kept unchanged on purpose.",
          "- No faults are injected: this measures the methods on real-world sensor disagreement only, not under the paper's attack model.", ""]
    path = pathlib.Path(out) / "summary.md"; path.write_text("\n".join(L), encoding="utf-8"); return path

# ---------------- driver ----------------
def _participant_name(path):
    return re.sub(r"_ppg_[A-Za-z0-9]+_w\d+(_[A-Za-z0-9]+)?$", "", pathlib.Path(path).stem)   # cache: <stem>_<channel>_w<s>[_<detector>]

def process(df, name, out):
    """Estimates, metrics and figures for one participant. Returns (windows-with-estimates DataFrame, metrics DataFrame)."""
    missing = [c for c in COLUMNS if c not in df.columns]
    if missing: raise ValueError(f"{name}: window table lacks columns {missing}")
    df, dropped = apply_exclusions(df.reset_index(drop=True), name)
    if dropped: print(f"{name}: excluded {len(dropped)} windows {dropped} (dataset notes, EXCLUDE)")
    d = pathlib.Path(out) / name; d.mkdir(parents=True, exist_ok=True)
    ests, lev = run_methods(df), activity_levels(df)
    res = _evaluate(ests, df["ecg_hr"].to_numpy(float), lev)
    win = df.assign(activity=lev, **{slug(m): ests[m] for m in METHOD_ORDER})
    win.attrs["excluded"] = dropped
    win.to_csv(d / "windows.csv", index=False); res.round(4).to_csv(d / "metrics.csv")
    _fig_accuracy(res, d / "fig_accuracy.png", f"WildPPG {name}: accuracy vs ECG per method (all windows)")
    _fig_mae_activity(res, d / "fig_mae_by_activity.png", f"WildPPG {name}: MAE by activity level")
    _fig_timeseries(df, ests, d / "fig_timeseries.png", f"WildPPG {name}: ECG vs PPG heart rate")
    _fig_errors(df, ests, d / "fig_errors.png", f"WildPPG {name}: absolute error per method")
    return win, res

def main(argv=None):
    ap = argparse.ArgumentParser(description="Base sensor-correction methods on real WildPPG heart rate (ECG answer key).")
    ap.add_argument("--participant", action="append", help="WildPPG .mat file (repeatable; default: all from wildppg.list_participants())")
    ap.add_argument("--channel", default="ppg_g", help="PPG channel used for extraction (default ppg_g)")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="output folder")
    ap.add_argument("--from-csv", action="append", dest="from_csv", help="precomputed window CSV instead of extracting (repeatable)")
    ap.add_argument("--include-noisy-ecg", action="store_true", help=f"also evaluate {sorted(NOISY_ECG)} (noisy ECG per the dataset notes)")
    a = ap.parse_args(argv)
    out = pathlib.Path(a.out); out.mkdir(parents=True, exist_ok=True)
    if a.from_csv: srcs = [(_participant_name(p), lambda p=p: pd.read_csv(p)) for p in a.from_csv]
    else:
        files = a.participant or wildppg.list_participants()
        if not files: raise SystemExit(f"no WildPPG files found in {wildppg.DATA_DIR}; pass --participant or --from-csv")
        srcs = [(pathlib.Path(p).stem, lambda p=p: wildppg.extract_windows(p, channel=a.channel)) for p in files]
    skipped = [] if a.include_noisy_ecg else [n for n, _ in srcs if _pid(n) in NOISY_ECG]
    if skipped: print(f"left out (noisy ECG per the dataset notes; --include-noisy-ecg to keep): {skipped}")
    srcs = [s for s in srcs if s[0] not in skipped]
    if not srcs: raise SystemExit("nothing left to evaluate")
    parts = []
    for name, load in srcs:
        win, res = process(load(), name, out); parts.append((name, win, res))
        print(f"\n=== {name}: {len(win)} windows ===\n{res.round(2).to_string()}")
    pooled = None
    if len(parts) > 1:
        win = pd.concat([w for _, w, _ in parts], ignore_index=True)
        pooled = _evaluate({m: win[slug(m)].to_numpy(float) for m in METHOD_ORDER}, win["ecg_hr"].to_numpy(float), win["activity"])
        pooled.round(4).to_csv(out / "pooled_metrics.csv"); print(f"\n=== pooled ({len(parts)} participants) ===\n{pooled.round(2).to_string()}")
    print(f"\nSummary: {write_summary(out, parts, pooled, skipped)}")
    return dict(parts=parts, pooled=pooled)


if __name__ == "__main__":
    main()
