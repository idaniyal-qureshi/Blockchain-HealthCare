"""Tests for code/extensions/data_layer/run_wildppg.py (base sensor-correction methods on real WildPPG heart rate).
Synthetic window tables with the exact wildppg columns: no real data, no neurokit2, no network."""
import sys, pathlib
import numpy as np, pandas as pd, pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "extensions" / "data_layer"))
import sensors
import run_wildppg as rw
from common import CFG

NAN = np.nan
pytestmark = pytest.mark.filterwarnings("ignore:(Mean of empty slice|All-NaN slice|Degrees of freedom):RuntimeWarning")   # all-NaN windows are expected

def make_df(T=120, seed=0, missing=0.1):
    r = np.random.default_rng(seed); hr = 70 + 10 * np.sin(np.arange(T) / 15)
    d = dict(window=np.arange(T), t_s=np.arange(T) * 8.0, ecg_hr=hr.copy())
    for i, loc in enumerate(rw.LOCATIONS):
        v = hr + r.normal(0, 0.5 + i, T); v[r.random(T) < missing] = NAN; d[loc] = v
    for loc in rw.LOCATIONS: d[f"motion_{loc}"] = r.random(T)
    df = pd.DataFrame(d); df.loc[3, "ecg_hr"] = NAN
    return df[rw.COLUMNS]

def test_columns_and_locations_match_wildppg():
    import wildppg
    assert rw.LOCATIONS == ("sternum", "head", "wrist", "ankle") and rw.COLUMNS == wildppg.COLUMNS

def test_readings_matrix_shape_and_order():
    df = make_df(10)[::-1]                                                # column order in the frame must not matter
    df = df[["ankle", *[c for c in df.columns if c != "ankle"]]]
    x = rw.readings_matrix(df)
    assert x.shape == (1, 10, 4)
    for i, loc in enumerate(rw.LOCATIONS): np.testing.assert_array_equal(x[0, :, i], df[loc].to_numpy(float))

def test_fig2_single_attempt_hand_cases():
    x = np.array([[[70, 70.2, 70.4, 70.6],        # clean: no flag, std < eps -> plain mean
                   [70, 70.2, 71, 90],            # one outlier: x_hat = 71, 90 flagged; eta = 1/4 -> median of rest
                   [70, NAN, NAN, 90],            # 3 of 4 flagged/missing -> unreliable -> quarantined
                   [70, 70.5, NAN, NAN]]])        # 2 missing (not > n/2): error; eta = 2/4 -> mode of rounded rest
    r = rw.fig2_single_attempt(x)
    np.testing.assert_allclose(r["eta"][0], np.cumsum([0, .25, .75, .5]) / np.arange(1, 5))
    # eta = [0, .125, .333, .375]: step1 -> mean branch of the rest, step3 -> median branch
    np.testing.assert_allclose(r["est"][0, :2], [70.3, np.mean([70, 70.2, 71])])
    assert np.isnan(r["est"][0, 2]) and r["quarantined"][0].tolist() == [False, False, True, False]
    assert r["est"][0, 3] == pytest.approx(70.25)                         # median branch (0.2 < 0.375 < 0.4)
    np.testing.assert_array_equal(r["flagged"][0, 1], [False, False, False, True])

def test_fig2_single_attempt_branches_single_step():
    one = lambda row: rw.fig2_single_attempt(np.array([[row]], float))["est"][0, 0]
    assert one([70, 70.2, 71, 90]) == pytest.approx(70.2)                 # eta 0.25 -> median of non-flagged
    assert one([70, 70.5, NAN, NAN]) == pytest.approx(70.0)               # eta 0.5 -> mode of rounded [70, 70]
    assert one([70, 70.2, 70.4, 70.6]) == pytest.approx(70.3)             # no error -> mean
    assert np.isnan(one([NAN, NAN, NAN, NAN])) and np.isnan(one([60, 70, 80, 90]))   # all missing / no agreement
    assert one([70, 71.4, 72.8, 73.0]) == pytest.approx(72.8)             # x_hat = 72.8 flags 70; eta .25 -> median of rest

@pytest.mark.parametrize("n_sensors", [4, 5])
def test_fig2_single_attempt_matches_base_pipeline_without_auth_and_retry(monkeypatch, n_sensors):
    """sensors.fig2_pipeline (authenticate=False, RETRY_K=0) fed our readings must give exactly fig2_single_attempt's output."""
    r = np.random.default_rng(3); P, T = 3, 60
    x = 75 + r.normal(0, 1.2, (P, T, n_sensors))
    x[r.random(x.shape) < 0.15] = NAN; spoof = r.random(x.shape) < 0.15; x[spoof] += r.choice([-25, -15, 15, 25], spoof.sum())
    monkeypatch.setattr(sensors, "N_S", n_sensors)
    monkeypatch.setattr(sensors, "draw_readings", lambda truth, fr, rng: (x.copy(), np.zeros(x.shape, np.int8)))
    monkeypatch.setitem(CFG, "RETRY_K", 0)
    base = sensors.fig2_pipeline(np.full((P, T), 75.0), 0.0, r, keys=None, authenticate=False)
    ours = rw.fig2_single_attempt(x)
    np.testing.assert_array_equal(base["quarantined"], ours["quarantined"])
    np.testing.assert_allclose(base["est"], ours["est"], equal_nan=True)
    assert ours["quarantined"].any() and (~ours["quarantined"]).any()

def test_run_methods_uses_base_functions():
    df = make_df(); x = rw.readings_matrix(df); T = len(df)
    ests = rw.run_methods(df)
    assert list(ests) == rw.METHOD_ORDER and all(np.shape(v) == (T,) for v in ests.values())
    for i, loc in enumerate(rw.LOCATIONS): np.testing.assert_array_equal(ests[rw.METHOD_ORDER[i]], df[loc].to_numpy(float))
    xh, fl, _ = sensors.algorithm1(x)
    np.testing.assert_allclose(ests["Median (Alg. 1)"], xh[0], equal_nan=True)
    np.testing.assert_allclose(ests["Mean smoothing"], np.nanmean(x, -1)[0], equal_nan=True)
    np.testing.assert_allclose(ests["Majority voting"], sensors.mode_rounded(x)[0], equal_nan=True)
    np.testing.assert_allclose(ests["Kalman filter"], sensors.agg_kalman(x)[0])
    np.testing.assert_allclose(ests["Adaptive (Alg. 2)"], sensors.algorithm2(x, sensors.fault_estimate(fl))[0], equal_nan=True)
    np.testing.assert_allclose(ests["Fig 2 pipeline (single attempt)"], rw.fig2_single_attempt(x)["est"][0], equal_nan=True)

def test_metrics_hand_computed():
    m = rw.metrics([70.5, NAN, 95, 60, 100], [70, 80, 90, NAN, 99.5])
    assert m["n"] == 4                                                     # truth-NaN window excluded
    assert m["MAE"] == pytest.approx((0.5 + 5 + 0.5) / 3) and m["RMSE"] == pytest.approx(np.sqrt((0.25 + 25 + 0.25) / 3))
    assert m["within_1_pct"] == pytest.approx(50.0)                       # NaN estimate counted wrong: 2 of 4
    assert m["within_5_pct"] == pytest.approx(75.0) and m["coverage_pct"] == pytest.approx(75.0)
    est, truth = np.array([70.5, NAN, 95, 99.5]), np.array([70, 80, 90, 99.5])
    assert rw.metrics(est, truth)["within_1_pct"] == pytest.approx(sensors.sensor_accuracy(est, truth))   # Eq 16 rule as the base
    e = rw.metrics([NAN, NAN], [70, 80]); assert e["n"] == 2 and e["within_1_pct"] == 0 and e["coverage_pct"] == 0 and np.isnan(e["MAE"])
    assert rw.metrics([1, 2], [NAN, NAN])["n"] == 0

def test_activity_levels_terciles():
    df = make_df(9); mot = np.arange(1, 10, dtype=float)
    for loc in rw.LOCATIONS: df[f"motion_{loc}"] = mot
    df.loc[0, "motion_head"] = NAN                                         # partial NaN: mean of the other 3
    lev = rw.activity_levels(df.sample(frac=1, random_state=1).sort_index())
    assert list(lev.cat.categories) == rw.ACTIVITY
    assert lev.tolist() == ["calm"] * 3 + ["moderate"] * 3 + ["active"] * 3
    for loc in rw.LOCATIONS: df.loc[4, f"motion_{loc}"] = NAN
    lev = rw.activity_levels(df)                                           # all 4 NaN -> no level; the other 8 split 3/2/3
    assert pd.isna(lev[4]) and lev.value_counts().reindex(rw.ACTIVITY).tolist() == [3, 2, 3]
    for loc in rw.LOCATIONS: df[f"motion_{loc}"] = 1.0                    # all ties still split into thirds
    assert rw.activity_levels(df).value_counts().tolist() == [3, 3, 3]

def test_evaluate_shape_and_consistency():
    df = make_df(); res = rw.evaluate(df)
    assert res.shape == (len(rw.METHOD_ORDER) * 4, len(rw.METRICS)) and list(res.columns) == rw.METRICS
    assert list(res.index.names) == ["method", "activity"]
    a = res.xs("all", level="activity"); assert (a["n"] == len(df) - 1).all()
    by = res.drop("all", level="activity").groupby(level="method")["n"].sum()
    assert (by == len(df) - 1).all()                                       # terciles partition the windows
    assert a.loc["Mean smoothing", "within_1_pct"] == pytest.approx(rw.metrics(rw.run_methods(df)["Mean smoothing"], df["ecg_hr"])["within_1_pct"])

def test_main_from_csv_writes_outputs(tmp_path, monkeypatch):
    monkeypatch.setitem(rw.plt.rcParams, "savefig.dpi", 50)
    paths = []
    for i, pid in enumerate(["zz1", "zz2"]):
        p = tmp_path / f"WildPPG_Part_{pid}_ppg_g_w8.csv"; make_df(90, seed=i).to_csv(p, index=False); paths.append(p)
    out = tmp_path / "out"
    res = rw.main(["--from-csv", str(paths[0]), "--from-csv", str(paths[1]), "--out", str(out)])
    for pid in ["zz1", "zz2"]:
        d = out / f"WildPPG_Part_{pid}"
        for f in ["windows.csv", "metrics.csv", "fig_accuracy.png", "fig_mae_by_activity.png", "fig_timeseries.png", "fig_errors.png"]:
            assert (d / f).stat().st_size > 0, f
        w = pd.read_csv(d / "windows.csv")
        assert len(w) == 90 and all(rw.slug(m) in w.columns for m in rw.METHOD_ORDER) and "activity" in w.columns
        assert pd.read_csv(d / "metrics.csv").shape == (40, 2 + len(rw.METRICS))
    assert pd.read_csv(out / "pooled_metrics.csv").query("activity == 'all'")["n"].eq(2 * 89).all()
    assert res["pooled"] is not None and len(res["parts"]) == 2
    s = (out / "summary.md").read_text(encoding="utf-8")
    for k in ["CC BY-NC-SA 4.0", "WildPPG_Part_zz1", "Pooled over 2", "92.1-96.7", "99.8 / 99.4 / 98.8 / 97.5 / 93.9", "Caveats"]: assert k in s

def test_process_rejects_missing_columns(tmp_path):
    with pytest.raises(ValueError, match="ecg_hr"): rw.process(make_df(10).drop(columns="ecg_hr"), "x", tmp_path)

def test_exclusions_drop_noted_windows(tmp_path, monkeypatch):
    assert rw.excluded_windows("an0") == [277, 278, 279]                  # 284543 // 1024 = 277, 286400 // 1024 = 279
    assert rw.excluded_windows("zz9") == [] and rw.excluded_windows("p", {"p": [(1023, 1024)]}) == [0, 1]
    df = make_df(300); kept, dropped = rw.apply_exclusions(df, "WildPPG_Part_an0")
    assert dropped == [277, 278, 279] and len(kept) == 297 and not kept["window"].isin(dropped).any()
    assert rw.apply_exclusions(df, "WildPPG_Part_xx1")[1] == []
    monkeypatch.setitem(rw.plt.rcParams, "savefig.dpi", 50)
    p = tmp_path / "WildPPG_Part_an0_ppg_g_w8.csv"; df.to_csv(p, index=False)
    res = rw.main(["--from-csv", str(p), "--out", str(tmp_path / "out")])
    w = pd.read_csv(tmp_path / "out" / "WildPPG_Part_an0" / "windows.csv")
    assert len(w) == 297 and res["parts"][0][2].loc[("Median (Alg. 1)", "all"), "n"] == 297 - 1   # window 3 has no ECG
    assert "3 windows excluded per the dataset notes (window 277, 278, 279)" in (tmp_path / "out" / "summary.md").read_text(encoding="utf-8")


def test_participant_name_strips_cache_suffix_with_and_without_detector():
    # regression: the detector suffix (wildppg.PPG_METHOD) must not leak into the participant id, or the dataset-notes
    # exclusions would silently stop applying
    for stem in ("WildPPG_Part_an0_ppg_g_w8", "WildPPG_Part_an0_ppg_g_w8_charlton", "WildPPG_Part_an0_ppg_ir_w8_elgendi"):
        assert rw._participant_name(f"/tmp/{stem}.csv") == "WildPPG_Part_an0"
    assert rw._participant_name("WildPPG_Part_an0.mat") == "WildPPG_Part_an0"
    assert rw.excluded_windows("an0") == [277, 278, 279]


def test_exclusions_for_all_noted_wrist_gaps():
    # dataset notes (MATLAB 1-based inclusive): k2s wrist 3786940-4194811 (53 min), l38 wrist 4337573-4545544 (27 min)
    L = 128 * 8
    assert rw.excluded_windows("k2s") == list(range((3786940 - 1) // L, (4194811 - 1) // L + 1))
    assert rw.excluded_windows("l38") == list(range((4337573 - 1) // L, (4545544 - 1) // L + 1))
    assert len(rw.excluded_windows("k2s")) * 8 / 60 == pytest.approx(53, abs=0.5)
    assert len(rw.excluded_windows("l38")) * 8 / 60 == pytest.approx(27, abs=0.5)
    assert set(rw.EXCLUDE) == {"an0", "k2s", "l38"}

def test_noisy_ecg_participants_left_out_unless_asked(tmp_path, monkeypatch):
    monkeypatch.setitem(rw.plt.rcParams, "savefig.dpi", 50)
    assert rw.NOISY_ECG == {"fex", "kjd", "p5d"}
    paths = []
    for i, pid in enumerate(["zz1", "fex"]):
        p = tmp_path / f"WildPPG_Part_{pid}_ppg_g_w8_charlton.csv"; make_df(60, seed=i).to_csv(p, index=False); paths.append(p)
    args = [a for p in paths for a in ("--from-csv", str(p))]
    res = rw.main(args + ["--out", str(tmp_path / "a")])
    assert [n for n, *_ in res["parts"]] == ["WildPPG_Part_zz1"] and res["pooled"] is None
    assert "Left out: `WildPPG_Part_fex`" in (tmp_path / "a" / "summary.md").read_text(encoding="utf-8")
    res = rw.main(args + ["--out", str(tmp_path / "b"), "--include-noisy-ecg"])
    assert len(res["parts"]) == 2 and res["pooled"] is not None
    assert "Left out" not in (tmp_path / "b" / "summary.md").read_text(encoding="utf-8")
    with pytest.raises(SystemExit):
        rw.main(["--from-csv", str(paths[1]), "--out", str(tmp_path / "c")])
