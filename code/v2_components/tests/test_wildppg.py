"""Tests for the WildPPG heart-rate extraction (code/extensions/data_layer/wildppg.py).

Pure tests need only numpy/scipy/pandas. The neurokit2 tests are skipped when it is not installed (CI), and none of the tests
need the real (gitignored, 1 GB) WildPPG files: a tiny .mat with the same nested struct layout is written to tmp_path instead.
"""
import inspect, pathlib, subprocess, sys
import numpy as np, pandas as pd, pytest, scipy.io

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "extensions" / "data_layer"))
import wildppg as W

FS, L = W.FS, W.FS * W.WIN_S   # 1024 samples per 8 s window

# ---------- hr_from_peaks ----------
def test_regular_peaks_give_exact_hr():
    hr = W.hr_from_peaks(np.arange(0, 3 * L, 96), 3 * L)   # 96 samples at 128 Hz = 0.75 s -> 80 bpm
    assert hr.shape == (3,) and np.allclose(hr, 80.0)

def test_n_windows_floor_and_peaks_past_end_ignored():
    peaks = np.arange(0, 5 * L, 128)                        # 60 bpm everywhere, incl. the partial tail
    hr = W.hr_from_peaks(peaks, 2 * L + 500)
    assert hr.shape == (2,) and np.allclose(hr, 60.0)
    assert W.hr_from_peaks(peaks, L - 1).shape == (0,)

def test_out_of_range_ibis_dropped():
    # IBIs of 0.25 s (240 bpm) and 2.0 s (30 bpm) are outside (60/185, 60/35) s; only the 1.0 s IBIs count
    p = np.array([0, 32, 160, 288, 416, 672])   # IBIs: 0.25, 1, 1, 1, 2 s
    assert W.hr_from_peaks(p, L)[0] == pytest.approx(60.0)
    assert np.isnan(W.hr_from_peaks(np.array([0, 300, 600]), L)[0])   # both 2.34 s IBIs dropped -> < 2 left -> NaN

def test_fewer_than_two_ibis_is_nan():
    assert np.isnan(W.hr_from_peaks(np.array([10, 138]), L)[0])            # one IBI
    assert np.isnan(W.hr_from_peaks(np.array([], dtype=int), L)[0])       # no beats
    assert np.isnan(W.hr_from_peaks(np.array([500]), L)[0])
    assert W.hr_from_peaks(np.array([10, 138, 266]), L)[0] == pytest.approx(60.0)

def test_ibi_across_window_boundary_not_used():
    # beats at 900, 1000 (window 0) and 1100, 1200 (window 1): the 1000->1100 IBI spans the boundary and is ignored,
    # leaving one IBI per window -> both NaN. Adding a third beat to window 1 gives it 2 IBIs.
    p = np.array([900, 1000, 1100, 1200])
    assert np.isnan(W.hr_from_peaks(p, 2 * L)).all()
    hr = W.hr_from_peaks(np.append(p, 1300), 2 * L)
    assert np.isnan(hr[0]) and hr[1] == pytest.approx(60 / (100 / FS))

def test_median_is_robust_to_one_odd_ibi():
    p = np.cumsum([0, 128, 128, 128, 160, 128])     # one 1.25 s IBI among 1.0 s ones
    assert W.hr_from_peaks(p, L)[0] == pytest.approx(60.0)

def test_strict_rule():
    two = np.array([0, 128, 256])                     # 2 regular IBIs: fine normally, too few for strict
    assert W.hr_from_peaks(two, L)[0] == pytest.approx(60.0)
    assert np.isnan(W.hr_from_peaks(two, L, strict=True)[0])
    regular = np.arange(0, L, 128)
    assert W.hr_from_peaks(regular, L, strict=True)[0] == pytest.approx(60.0)
    irregular = np.cumsum([0, 128, 128, 90, 128])    # min/max = 90/128 = 0.70 < 0.75
    assert np.isfinite(W.hr_from_peaks(irregular, L)[0])
    assert np.isnan(W.hr_from_peaks(irregular, L, strict=True)[0])
    mild = np.cumsum([0, 128, 128, 100, 128])         # 100/128 = 0.78 >= 0.75 -> kept
    assert np.isfinite(W.hr_from_peaks(mild, L, strict=True)[0])

def test_unsorted_peaks_and_other_fs():
    p = np.arange(0, 2 * 2000, 250)                   # fs=250, win_s=8 -> 2000-sample windows, 1 s IBIs
    assert np.allclose(W.hr_from_peaks(p[::-1], 4000, fs=250), 60.0)

# ---------- motion, channel, files ----------
def test_motion_per_window():
    a = np.concatenate([np.ones(L), np.tile([0.0, 2.0], L // 2), np.ones(100)])
    m = W.motion_per_window(a)
    assert m.shape == (2,) and m[0] == pytest.approx(0.0) and m[1] == pytest.approx(1.0)

def test_channel_validation(tmp_path):
    with pytest.raises(ValueError):
        W.load_participant(tmp_path / "x.mat", channel="ecg")
    with pytest.raises(ValueError):
        W.extract_windows(tmp_path / "x.mat", channel="ppg_blue")

def test_list_participants(tmp_path):
    for n in ["WildPPG_Part_b.mat", "WildPPG_Part_a.mat", "other.mat", "WildPPG_Part_c.csv"]:
        (tmp_path / n).write_bytes(b"")
    assert [p.name for p in W.list_participants(tmp_path)] == ["WildPPG_Part_a.mat", "WildPPG_Part_b.mat"]
    assert W.list_participants(tmp_path / "missing") == []

N_SYN = 3 * L + 100   # 3 full windows plus a partial tail

def _trace(v, descr):
    return {"fs": FS, "descr": descr, "v": np.asarray(v, dtype=float)}

def _write_mat(path):
    """Tiny file with the real WildPPG layout: location structs -> trace structs (fs, descr, v); ECG on sternum only."""
    rng = np.random.default_rng(0); t = np.arange(N_SYN)
    mat = {"id": "syn", "notes": "synthetic"}
    for k, loc in enumerate(W.LOCATIONS):
        s = {f"acc_{ax}": _trace(rng.normal(0, 0.1 * (k + 1), N_SYN) + (1.0 if ax == "z" else 0.0), ax) for ax in "xyz"}
        for c, ch in enumerate(W.CHANNELS):
            s[ch] = _trace(0.5 + 0.01 * (k + 1) * (c + 1) * np.sin(2 * np.pi * t / FS), ch)
        s["altitude"] = _trace(np.zeros(N_SYN), "alt"); s["temperature"] = _trace(np.full(N_SYN, 30.0), "temp")
        if loc == "sternum":
            s["ecg"] = _trace(np.arange(N_SYN) % 1000, "ecg")
        mat[loc] = s
    scipy.io.savemat(path, mat)
    return path

def test_load_participant_synthetic(tmp_path):
    p = _write_mat(tmp_path / "WildPPG_Part_syn.mat")
    d = W.load_participant(p, channel="ppg_ir")
    assert d["id"] == "syn" and d["fs"] == 128
    assert d["ecg"].dtype == float and d["ecg"].shape == (N_SYN,) and d["ecg"][5] == 5.0
    assert set(d["ppg"]) == set(d["acc"]) == set(W.LOCATIONS)
    t = np.arange(N_SYN)
    assert np.allclose(d["ppg"]["head"], 0.5 + 0.01 * 2 * 2 * np.sin(2 * np.pi * t / FS))   # head = k 1, ppg_ir = c 1
    raw = scipy.io.loadmat(p, squeeze_me=True, struct_as_record=False)["wrist"]
    assert np.allclose(d["acc"]["wrist"], np.sqrt(raw.acc_x.v ** 2 + raw.acc_y.v ** 2 + raw.acc_z.v ** 2))

def _fake_beats(calls, step0=128, dstep=8):
    """Fake beat detector (no neurokit): call k (1 = ECG, 2-5 = sternum..ankle) gives beats every step0 - dstep*k samples."""
    def fake(x, **kw):
        calls.append(len(x)); return np.arange(0, len(x), step0 - dstep * len(calls))
    return fake

def test_extract_windows_synthetic_cache_and_beats(tmp_path, monkeypatch):
    p = _write_mat(tmp_path / "WildPPG_Part_syn.mat")
    calls = []; fake = _fake_beats(calls)
    monkeypatch.setattr(W, "ecg_beats", fake); monkeypatch.setattr(W, "ppg_beats", fake)
    df = W.extract_windows(p, channel="ppg_g", cache_dir=tmp_path / "cache")
    assert list(df.columns) == ["window", "t_s", "ecg_hr", "sternum", "head", "wrist", "ankle",
                                "motion_sternum", "motion_head", "motion_wrist", "motion_ankle"]
    assert len(df) == 3 and calls == [N_SYN] * 5
    assert df["window"].tolist() == [0, 1, 2] and df["t_s"].tolist() == [0.0, 8.0, 16.0]
    assert np.allclose(df["ecg_hr"], 60 * FS / 120) and np.allclose(df["ankle"], 60 * FS / 88)   # 64.0 and 87.27 bpm
    assert (df["motion_ankle"] > df["motion_sternum"]).all()     # synthetic acc noise grows with location index
    csv, npz = W.cache_paths(p, "ppg_g", tmp_path / "cache")
    assert csv.name == f"WildPPG_Part_syn_ppg_g_w8_{W.PPG_METHOD}.csv" and csv.exists()
    assert npz.name == f"WildPPG_Part_syn_ppg_g_w8_{W.PPG_METHOD}_beats.npz" and npz.exists()
    again = W.extract_windows(p, channel="ppg_g", cache_dir=tmp_path / "cache")   # served from cache: no recomputation
    assert len(calls) == 5
    pd.testing.assert_frame_equal(again, df, check_dtype=False)
    W.extract_windows(p, channel="ppg_g", cache=False, cache_dir=tmp_path / "cache")  # cache=False recomputes
    assert len(calls) == 10

def test_saved_beats_roundtrip_and_rebuild_windows(tmp_path, monkeypatch):
    p = _write_mat(tmp_path / "WildPPG_Part_syn.mat")
    calls = []; monkeypatch.setattr(W, "ecg_beats", _fake_beats(calls)); monkeypatch.setattr(W, "ppg_beats", _fake_beats(calls))
    df = W.extract_windows(p, cache_dir=tmp_path)
    b = W.load_beats(W.cache_paths(p, "ppg_g", tmp_path)[1])
    assert set(b) == {"ecg", *W.LOCATIONS, "fs", "n_samples", "channel", "ppg_method"}
    assert b["fs"] == FS and b["n_samples"] == N_SYN and b["channel"] == "ppg_g" and b["ppg_method"] == W.PPG_METHOD
    assert np.array_equal(b["ecg"], np.arange(0, N_SYN, 120)) and b["head"].dtype == np.int64
    rebuilt = W.windows_from_beats(b)              # same 8 s windows -> identical HR columns, without the raw file
    pd.testing.assert_frame_equal(rebuilt, df[["window", "t_s", "ecg_hr", *W.LOCATIONS]], check_dtype=False)
    assert len(W.windows_from_beats(b, win_s=4)) == N_SYN // (FS * 4)   # another window length works too

def test_chunked_peaks_stitches_chunks_without_duplicates():
    # fake detector returns beats every 100 samples of whatever (padded) segment it gets; chunk = 2 windows, pad = 1 window
    det = lambda seg: np.arange(0, len(seg), 100)
    pk = W._chunked_peaks(np.zeros(6 * L), det, FS, W.WIN_S, 2 * W.WIN_S, "t")
    assert np.all(np.diff(pk) > 0) and pk.min() >= 0 and pk.max() < 6 * L          # sorted, unique, in range
    for s in range(0, 6 * L, 2 * L):                                                  # each chunk keeps only its own beats
        own = pk[(pk >= s) & (pk < s + 2 * L)]
        start = 0 if s == 0 else s - L                                                # segment start incl. padding
        assert np.array_equal(own, [q for q in range(start, s + 2 * L + L, 100) if s <= q < s + 2 * L])

def test_failed_chunk_gives_nan_windows_only_there():
    def det(seg):                                       # fails when the (padded) segment is mostly saturated
        if seg.mean() > 0.5: raise ValueError("saturated")
        return np.arange(0, len(seg), 96)                                             # 80 bpm
    x = np.zeros(4 * L); x[2 * L:] = 1.0                # chunk 1 = windows 0-1 (1/3 of its padded segment saturated): ok
    hr = W.hr_from_peaks(W._chunked_peaks(x, det, FS, W.WIN_S, 2 * W.WIN_S, "t"), len(x))   # chunk 2 = windows 2-3: fails
    assert np.allclose(hr[:2], 80.0) and np.isnan(hr[2:]).all()

def test_extract_windows_default_cache_dir(tmp_path, monkeypatch):
    p = _write_mat(tmp_path / "WildPPG_Part_syn.mat")
    monkeypatch.setattr(W, "ecg_beats", lambda x, **kw: np.zeros(0, np.int64))        # no ECG beats -> NaN answer key
    monkeypatch.setattr(W, "ppg_beats", lambda x, **kw: np.arange(0, len(x), 128))
    df = W.extract_windows(p, channel="ppg_r")
    assert (tmp_path / f"WildPPG_Part_syn_ppg_r_w8_{W.PPG_METHOD}.csv").exists() and df["ecg_hr"].isna().all()

def test_default_detector_is_charlton_and_named_in_cache():
    assert W.PPG_METHOD == "charlton"
    assert inspect.signature(W.ppg_window_hr).parameters["method"].default == W.PPG_METHOD

def test_shorter_ppg_is_padded_not_crashing(tmp_path, monkeypatch):
    # a PPG result shorter than the ECG (e.g. a device that stopped early) must give NaN windows, not a length error
    p = _write_mat(tmp_path / "WildPPG_Part_syn.mat")
    monkeypatch.setattr(W, "ecg_beats", lambda x, **kw: np.arange(0, len(x), 128))
    monkeypatch.setattr(W, "load_participant", (lambda orig: lambda path, ch: (lambda d: {**d, "ppg": {k: v[:2 * L] for k, v in d["ppg"].items()}})(orig(path, ch)))(W.load_participant))
    monkeypatch.setattr(W, "ppg_beats", lambda x, **kw: np.arange(0, len(x), 128))   # PPG traces end one window early
    df = W.extract_windows(p, cache=False)
    assert len(df) == 3 and df["head"].tolist()[:2] == [60.0, 60.0] and np.isnan(df["head"].iloc[2])

def test_fit_truncates_and_pads():
    assert W._fit([1, 2, 3], 2).tolist() == [1.0, 2.0]
    out = W._fit([1], 3)
    assert out[0] == 1.0 and np.isnan(out[1:]).all()

def test_chunk_must_align_with_windows():
    for f in (W.ecg_window_hr, W.ppg_window_hr):     # checked before neurokit2 is imported, so this runs in CI too
        with pytest.raises(AssertionError):
            f(np.zeros(4 * L), chunk_s=12)

def test_module_import_does_not_need_neurokit():
    # fresh interpreter: importing wildppg must not pull in neurokit2 (CI has none); it is imported inside the signal functions
    code = f"import sys; sys.path.insert(0, {str(pathlib.Path(W.__file__).parent)!r}); import wildppg; print('neurokit2' in sys.modules)"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout.strip()
    assert out == "False"

# ---------- neurokit2 (skipped in CI) ----------
def test_ecg_window_hr_simulated():
    nk = pytest.importorskip("neurokit2")
    ecg = nk.ecg_simulate(duration=120, sampling_rate=FS, heart_rate=72, random_state=0)
    hr = W.ecg_window_hr(ecg, chunk_s=64)          # small chunks also exercise the chunk stitching
    assert hr.shape == (15,) and np.isfinite(hr).sum() >= 12
    assert abs(np.nanmedian(hr) - 72) < 1.5 and np.nanmax(np.abs(hr - 72)) < 4

def test_ppg_window_hr_simulated():
    # Polarity: ppg_window_hr negates its input because on the real WildPPG data the negated signal matched the ECG better
    # at every location (see wildppg.py). neurokit's simulator has the same orientation as the raw WildPPG values (sharp
    # upstroke at each beat, slow decay: the signal rises during only ~25% of samples here, ~35% on calm real head/wrist
    # data), so feeding it unchanged tests the real-data convention.
    nk = pytest.importorskip("neurokit2")
    ppg = nk.ppg_simulate(duration=120, sampling_rate=FS, heart_rate=72, frequency_modulation=0, ibi_randomness=0, random_state=0)
    assert np.mean(np.diff(nk.ppg_clean(ppg, sampling_rate=FS)) > 0) < 0.4
    hr = W.ppg_window_hr(ppg)
    assert hr.shape == (15,) and np.isfinite(hr).all() and np.abs(hr - 72).max() < 1.5

def test_flat_signal_does_not_crash():
    pytest.importorskip("neurokit2")
    hr = W.ppg_window_hr(np.full(3 * L, 1.0))       # saturated sensor
    assert hr.shape == (3,) and np.isnan(hr).all()
