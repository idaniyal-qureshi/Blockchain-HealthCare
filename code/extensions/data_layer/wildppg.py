"""Data layer: per-window heart rate (HR) from the WildPPG dataset (real wearable PPG + ECG recordings)

* WildPPG (Meier, Demirel, Holz, "WildPPG: A Real-World PPG Dataset of Long Continuous Recordings", NeurIPS 2024 Datasets and
  Benchmarks, ETH Zurich): 16 participants, each recorded for about a day outdoors with 4 body-worn devices at forehead ("head"),
  sternum, wrist and ankle. Every device logs 3-wavelength PPG (ppg_g / ppg_ir / ppg_r), a 3-axis accelerometer, altitude and
  temperature at 128 Hz; the sternum device also logs a Lead-I ECG. One .mat file per participant (WildPPG_Part_<id>.mat).
* LICENCE: the data is CC BY-NC-SA 4.0 (non-commercial, attribution, share-alike). The .mat files and the CSV caches made here live
  in data/ (gitignored): do not commit or redistribute them.
* WHY EXTRACT: the files hold raw waveforms, not heart rates. The 4 PPG devices are 4 real, co-located sensors of one quantity
  (HR), and the ECG gives the reference ("answer key"). HR is obtained by detecting beats (neurokit2) and timing them.
* WINDOWING: non-overlapping WIN_S = 8 s windows. Per window, inter-beat intervals (IBIs) come only from consecutive beats that
  both lie inside the window; IBIs outside (60/185, 60/35) s (the paper's 35-185 bpm limits, Sec 3.3.1) are dropped;
  HR = 60 / median(IBI); NaN if < 2 IBIs remain.
* ECG CLEANING (answer key only, strict=True): a window also needs >= 3 IBIs and min(IBI)/max(IBI) >= 0.75, else NaN. This is OUR
  APPROXIMATION of the WildPPG authors' regularity-based cleaning of the ECG reference, not their exact procedure.
* PPG BEAT DETECTOR: neurokit2's "charlton" method (MSPTDfast, Charlton et al.; the WildPPG authors also used Charlton's
  ppg-beats toolbox for their baselines), the same for all four locations. It replaced neurokit2's default Elgendi detector after
  a comparison on participant an0 (full 12.3 h, ppg_g; % of ECG windows within ±1 / ±5 bpm, a missing reading counted wrong):
  ankle 12.0/41.0 -> 18.2/53.7, sternum 19.3/35.4 -> 27.0/50.7, wrist 43.1/72.2 -> 47.6/80.5, head 47.7/80.2 -> 48.6/80.6.
  The ECG is used only to score detectors, never to pick a reading per window.
* PPG POLARITY (chosen empirically): the waveform is NEGATED before beat detection. On an0 the negated signal tracked the ECG better
  at every location with both detectors (Elgendi, full 12.3 h: MAE head 4.3 vs 5.6, wrist 5.6 vs 6.7, ankle 13.2 vs 14.0, sternum
  14.5 vs 15.7 bpm; Charlton, hours 8-10, ±1 %: head 60.8 vs 41.0, wrist 54.0 vs 33.5, ankle 18.3 vs 17.6, sternum 23.6 vs 11.6).
  R-peak-aligned averages show the raw values rise SHARPLY at pulse arrival and decay slowly, so after negation the detector locks
  onto the sharp pulse onset (foot), a steadier beat marker than the rounded systolic peak.
* neurokit2 is imported lazily inside the two signal functions so this module (and its pure tests) work without it.

Pure library (numpy, scipy, pandas; neurokit2 only for beat detection). It does not import or modify the base code.
"""
import pathlib, sys, warnings
import numpy as np, pandas as pd, scipy.io

FS = 128; WIN_S = 8
LOCATIONS = ("sternum", "head", "wrist", "ankle")
CHANNELS = ("ppg_g", "ppg_ir", "ppg_r")
DATA_DIR = pathlib.Path(__file__).resolve().parent / "data" / "wildppg"
IBI_MIN, IBI_MAX = 60 / 185, 60 / 35          # seconds; paper Sec 3.3.1 HR limits 35..185 bpm
STRICT_MIN_IBIS, STRICT_MIN_RATIO = 3, 0.75   # ECG answer-key regularity rule (approximation, see docstring)
PPG_METHOD = "charlton"                       # neurokit2 PPG beat detector (see docstring); part of the cache file name
COLUMNS = ["window", "t_s", "ecg_hr", *LOCATIONS, *(f"motion_{loc}" for loc in LOCATIONS)]

def _log(msg):
    print(f"[wildppg] {msg}", file=sys.stderr, flush=True)

def list_participants(data_dir=DATA_DIR):
    """Sorted WildPPG_Part_*.mat files in data_dir."""
    return sorted(pathlib.Path(data_dir).glob("WildPPG_Part_*.mat"))

def _check_channel(channel):
    if channel not in CHANNELS:
        raise ValueError(f"channel must be one of {CHANNELS}, got {channel!r}")

def load_participant(path, channel="ppg_g"):
    """Load ECG, one PPG channel and acceleration magnitude for every location. Each trace is a struct whose samples are in .v."""
    _check_channel(channel)
    path = pathlib.Path(path)
    m =scipy.io.loadmat(path, squeeze_me=True, struct_as_record=False, variable_names=list(LOCATIONS))
    v = lambda loc, trace: np.asarray(getattr(m[loc], trace).v, dtype=float)
    return {
        "id": path.stem.replace("WildPPG_Part_", ""),
        "fs": FS,
        "ecg": v("sternum", "ecg"),       # only the sternum device carries an ECG
        "ppg": {loc: v(loc, channel) for loc in LOCATIONS},
        "acc": {loc: np.sqrt(v(loc, "acc_x") ** 2 + v(loc, "acc_y") ** 2 + v(loc, "acc_z") ** 2) for loc in LOCATIONS},
    }

def hr_from_peaks(peaks, n_samples, fs=FS, win_s=WIN_S, strict=False):
    """Per-window HR (bpm) from beat sample indices. n_windows = n_samples // (fs*win_s); see module docstring for the rules."""
    L = int(fs * win_s); n_win = int(n_samples) // L
    hr = np.full(n_win, np.nan)
    p = np.sort(np.asarray(peaks, dtype=np.int64))
    p = p[(p >= 0) & (p < n_win * L)]
    if n_win == 0 or len(p) < 2:
        return hr
    w = p // L
    same = w[1:] == w[:-1]                     # IBI counts only if both beats are in the same window
    ibi, iw = (np.diff(p) / fs)[same], w[1:][same]
    keep = (ibi > IBI_MIN) & (ibi < IBI_MAX)
    ibi, iw = ibi[keep], iw[keep]
    bounds = np.searchsorted(iw, np.arange(n_win + 1))   # iw is sorted, so each window's IBIs are a contiguous slice
    for k in range(n_win):
        x = ibi[bounds[k]:bounds[k + 1]]
        if len(x) < 2:
            continue
        if strict and (len(x) < STRICT_MIN_IBIS or x.min() / x.max() < STRICT_MIN_RATIO):
            continue
        hr[k] = 60.0 / np.median(x)
    return hr

def _check_chunk(chunk_s, win_s):
    assert chunk_s % win_s == 0, "chunk_s must be a multiple of win_s so chunks align with windows"

def _chunked_peaks(x, detect, fs, win_s, chunk_s, label):
    """Run detect(segment) -> beat indices chunk by chunk (chunks aligned to windows), each chunk padded by one window on both sides
    so filters settle; only beats inside the chunk itself are kept. Returns sorted beat sample indices of the whole signal (int64).
    A chunk where detection fails (flat / saturated / NaN signal: neurokit can raise) contributes no beats, so its windows get NaN HR."""
    x = np.asarray(x, dtype=float)
    L, C, pad = int(fs * win_s), int(fs * chunk_s), int(fs * win_s)
    n_win = len(x) // L; end = n_win * L
    _check_chunk(chunk_s, win_s)
    out = []
    for s in range(0, end, C):
        e = min(s + C, end)
        a, b = max(0, s - pad), min(len(x), e + pad)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                pk = np.asarray(detect(x[a:b]), dtype=np.int64) + a
            out.append(pk[(pk >= s) & (pk < e)])
        except Exception as err:
            _log(f"{label}: chunk at {s / fs:.0f} s failed ({type(err).__name__}: {err}); windows set to NaN")
    return np.unique(np.concatenate(out)) if out else np.zeros(0, np.int64)

def ecg_beats(ecg, fs=FS, win_s=WIN_S, chunk_s=1800):
    """ECG R-peak sample indices: neurokit clean + Pan-Tompkins."""
    _check_chunk(chunk_s, win_s)
    import neurokit2 as nk
    detect = lambda seg: nk.ecg_peaks(nk.ecg_clean(seg, sampling_rate=fs), sampling_rate=fs, method="pantompkins1985")[1]["ECG_R_Peaks"]
    return _chunked_peaks(ecg, detect, fs, win_s, chunk_s, "ecg")

def ppg_beats(ppg, fs=FS, win_s=WIN_S, chunk_s=1800, method=PPG_METHOD):
    """PPG beat sample indices: signal negated (empirical choice, see module docstring), neurokit clean + `method` beat detection."""
    _check_chunk(chunk_s, win_s)
    import neurokit2 as nk
    detect = lambda seg: nk.ppg_peaks(nk.ppg_clean(-seg, sampling_rate=fs), sampling_rate=fs, method=method)[1]["PPG_Peaks"]
    return _chunked_peaks(ppg, detect, fs, win_s, chunk_s, f"ppg-{method}")

def ecg_window_hr(ecg, fs=FS, win_s=WIN_S, chunk_s=1800):
    """Per-window ECG HR (the answer key): R peaks + strict regularity rule."""
    return hr_from_peaks(ecg_beats(ecg, fs, win_s, chunk_s), len(ecg), fs, win_s, strict=True)

def ppg_window_hr(ppg, fs=FS, win_s=WIN_S, chunk_s=1800, method=PPG_METHOD):
    """Per-window PPG HR from ppg_beats."""
    return hr_from_peaks(ppg_beats(ppg, fs, win_s, chunk_s, method), len(ppg), fs, win_s, strict=False)

def _fit(a, n):
    """First n values of a, padded with NaN if a is shorter (e.g. a PPG trace that ends before the ECG)."""
    out = np.full(n, np.nan); a = np.asarray(a, dtype=float)[:n]; out[:len(a)] = a
    return out

def motion_per_window(acc_mag, fs=FS, win_s=WIN_S):
    """Std of the acceleration magnitude per window (a simple motion-intensity score; gravity cancels out in the std)."""
    L = int(fs * win_s); a = np.asarray(acc_mag, dtype=float)
    n_win = len(a) // L
    return a[:n_win * L].reshape(n_win, L).std(axis=1)

def cache_paths(path, channel="ppg_g", cache_dir=None):
    """(window CSV, beat-times .npz) for a participant file. The detector is in both names so a cache made with another detector
    is never reused by mistake."""
    path = pathlib.Path(path); base = pathlib.Path(cache_dir or path.parent) / f"{path.stem}_{channel}_w{WIN_S}_{PPG_METHOD}"
    return base.with_name(base.name + ".csv"), base.with_name(base.name + "_beats.npz")

def extract_windows(path, channel="ppg_g", cache=True, cache_dir=None):
    """Per-window table for one participant (columns COLUMNS). With cache=True it is saved as <stem>_<channel>_w<WIN_S>_<PPG_METHOD>.csv
    next to the .mat (or in cache_dir), together with the detected beat times (<...>_beats.npz, see save_beats), and reloaded from
    the CSV when it already exists."""
    _check_channel(channel)
    path = pathlib.Path(path)
    csv_path, beats_path = cache_paths(path, channel, cache_dir)
    if cache and csv_path.exists():
        _log(f"loading cache {csv_path.name}")
        return pd.read_csv(csv_path)[COLUMNS]
    _log(f"loading {path.name} ({channel})")
    d = load_participant(path, channel)
    n_samples = len(d["ecg"]); n_win = n_samples // (FS * WIN_S)
    df = pd.DataFrame({"window": np.arange(n_win, dtype=int), "t_s": np.arange(n_win, dtype=float) * WIN_S})
    _log("ECG answer key"); beats = {"ecg": ecg_beats(d["ecg"])}
    df["ecg_hr"] = _fit(hr_from_peaks(beats["ecg"], n_samples, strict=True), n_win)
    for loc in LOCATIONS:
        _log(f"PPG {loc}"); beats[loc] = ppg_beats(d["ppg"][loc])
        df[loc] = _fit(hr_from_peaks(beats[loc], len(d["ppg"][loc])), n_win)
    for loc in LOCATIONS:
        df[f"motion_{loc}"] = _fit(motion_per_window(d["acc"][loc]), n_win)
    df = df[COLUMNS]
    if cache:
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        save_beats(beats_path, beats, n_samples, channel)
        df.to_csv(csv_path, index=False)          # written last: a CSV on disk means the participant is complete
        _log(f"wrote {csv_path} and {beats_path.name}")
    return df

def save_beats(path, beats, n_samples, channel):
    """Beat sample indices per signal (ecg + the 4 PPG locations) plus what is needed to rebuild windows later without the raw
    file: fs, n_samples, channel and detector. A few MB per participant."""
    np.savez_compressed(path, **{k: np.asarray(v, dtype=np.int64) for k, v in beats.items()}, fs=FS, n_samples=n_samples,
                        channel=channel, ppg_method=PPG_METHOD)

def load_beats(path):
    """Inverse of save_beats: dict with 'ecg', the 4 locations (int64 arrays), 'fs', 'n_samples' (int), 'channel', 'ppg_method' (str)."""
    with np.load(path, allow_pickle=False) as z:
        out = {k: z[k] for k in ("ecg", *LOCATIONS)}
        out.update(fs=int(z["fs"]), n_samples=int(z["n_samples"]), channel=str(z["channel"]), ppg_method=str(z["ppg_method"]))
    return out

def windows_from_beats(beats, win_s=WIN_S):
    """Per-window HR table (window, t_s, ecg_hr, 4 locations) rebuilt from saved beat times, e.g. to try another window length
    without re-downloading the raw file. Motion is not stored with the beats, so it is not included."""
    fs, n = beats["fs"], beats["n_samples"]; n_win = n // (fs * win_s)
    df = pd.DataFrame({"window": np.arange(n_win, dtype=int), "t_s": np.arange(n_win, dtype=float) * win_s})
    df["ecg_hr"] = hr_from_peaks(beats["ecg"], n, fs, win_s, strict=True)
    for loc in LOCATIONS:
        df[loc] = hr_from_peaks(beats[loc], n, fs, win_s)
    return df
