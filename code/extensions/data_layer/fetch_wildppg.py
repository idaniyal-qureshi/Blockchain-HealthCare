"""Download -> extract -> check -> delete, one WildPPG participant at a time, so the 1.1-1.4 GB raw files never pile up on disk.

For every participant on the authors' public share (https://polybox.ethz.ch/index.php/s/NWTuyNojU7aya1y, folder data/):
  1. skip it if its window CSV and beat-times file already exist (so an interrupted run can simply be started again);
  2. check there is enough free disk space, then download WildPPG_Part_<id>.mat (to a .part file, renamed when complete and the
     size matches the share's listing);
  3. extract it with wildppg.extract_windows (the same code used for every participant): window CSV + beat times (.npz);
  4. check the result (columns, length, ECG coverage, HR range, beat file consistent with the table);
  5. only if the check passes, delete the raw .mat (unless --keep-raw). If it fails, the raw file is kept for inspection and the
     bad outputs are removed, so the participant is retried next time.
Nothing is lost permanently: the dataset stays on the share and extraction is deterministic, so a re-download gives the same table.
Licence: CC BY-NC-SA 4.0 (see wildppg.py); everything is written to data/wildppg/, which is gitignored.

    python code/extensions/data_layer/fetch_wildppg.py --list          # what is on the share and what is done locally
    python code/extensions/data_layer/fetch_wildppg.py                 # all participants not done yet (one at a time)
    python code/extensions/data_layer/fetch_wildppg.py --only e61      # just one participant
"""
import argparse, base64, pathlib, shutil, sys, time, urllib.request
import xml.etree.ElementTree as ET
import numpy as np, pandas as pd
import wildppg

SHARE_TOKEN = "NWTuyNojU7aya1y"                                   # public share token (it is the share's public URL)
WEBDAV = "https://polybox.ethz.ch/public.php/webdav/data/"
MARGIN = 512 * 2 ** 20                                            # keep this much disk free on top of the download
MIN_WINDOWS, MIN_ECG_FRACTION = 3000, 0.5                         # >= 6.7 h recorded, ECG answer in at least half the windows
LOG = wildppg.DATA_DIR / "fetch_log.txt"

def _log(msg):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line, flush=True)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f: f.write(line + "\n")

def _request(url, method="GET", headers=None):
    auth = base64.b64encode(f"{SHARE_TOKEN}:".encode()).decode()
    return urllib.request.Request(url, method=method, headers={"Authorization": f"Basic {auth}", **(headers or {})})

def parse_listing(xml_text):
    """{file name: size in bytes} for the WildPPG_Part_*.mat entries of a WebDAV PROPFIND response."""
    ns = {"d": "DAV:"}; out = {}
    for r in ET.fromstring(xml_text).findall("d:response", ns):
        name = r.findtext("d:href", "", ns).rstrip("/").rsplit("/", 1)[-1]
        size = r.findtext(".//d:getcontentlength", None, ns)
        if name.startswith("WildPPG_Part_") and name.endswith(".mat") and size is not None:
            out[name] = int(size)
    return dict(sorted(out.items()))

def list_remote():
    with urllib.request.urlopen(_request(WEBDAV, "PROPFIND", {"Depth": "1"}), timeout=60) as resp:
        return parse_listing(resp.read().decode("utf-8"))

def is_done(name, data_dir=wildppg.DATA_DIR):
    csv, npz = wildppg.cache_paths(pathlib.Path(data_dir) / name)
    return csv.exists() and npz.exists()

def download(name, size, data_dir=wildppg.DATA_DIR, retries=3):
    """Stream the file to <name>.part, check the byte count against the listing, then rename. Returns the final path."""
    dest = pathlib.Path(data_dir) / name; part = dest.with_name(name + ".part")
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(_request(WEBDAV + name), timeout=120) as resp, open(part, "wb") as f:
                shutil.copyfileobj(resp, f, 8 * 2 ** 20)
            if part.stat().st_size != size:
                raise IOError(f"size {part.stat().st_size} != expected {size}")
            part.replace(dest); return dest
        except Exception as err:
            _log(f"{name}: download attempt {attempt}/{retries} failed ({type(err).__name__}: {err})")
            part.unlink(missing_ok=True); time.sleep(10 * attempt)
    raise RuntimeError(f"{name}: download failed {retries} times")

def check_outputs(mat_path):
    """List of problems with the extracted outputs of one participant (empty list = OK)."""
    csv, npz = wildppg.cache_paths(mat_path); problems = []
    if not (csv.exists() and npz.exists()):
        return ["window CSV or beat file missing"]
    df = pd.read_csv(csv)
    if list(df.columns) != wildppg.COLUMNS: problems.append(f"unexpected columns {list(df.columns)}")
    if len(df) < MIN_WINDOWS: problems.append(f"only {len(df)} windows (< {MIN_WINDOWS})")
    if df["window"].tolist() != list(range(len(df))): problems.append("window index is not 0..n-1")
    ecg_ok = df["ecg_hr"].notna().mean()
    if ecg_ok < MIN_ECG_FRACTION: problems.append(f"ECG answer in only {ecg_ok:.0%} of windows")
    hr = df[["ecg_hr", *wildppg.LOCATIONS]].to_numpy(float); hr = hr[np.isfinite(hr)]
    if len(hr) and (hr.min() < 35 or hr.max() > 185): problems.append("heart rate outside 35-185 bpm")
    b = wildppg.load_beats(npz)
    if b["n_samples"] // (b["fs"] * wildppg.WIN_S) != len(df): problems.append("beat file does not match the window table")
    return problems

def process(name, size, keep_raw=False, data_dir=wildppg.DATA_DIR):
    """Download, extract, check and (if OK) delete one participant. Returns 'skipped', 'done' or 'failed'."""
    data_dir = pathlib.Path(data_dir)
    if is_done(name, data_dir):
        _log(f"{name}: already extracted, skipped"); return "skipped"
    mat = data_dir / name
    if not mat.exists():
        free = shutil.disk_usage(data_dir).free
        if free < size + MARGIN:
            raise RuntimeError(f"{name}: not enough disk space ({free / 2**30:.1f} GB free, need {(size + MARGIN) / 2**30:.1f} GB)")
        _log(f"{name}: downloading {size / 2**30:.2f} GB"); t = time.time()
        download(name, size, data_dir); _log(f"{name}: downloaded in {time.time() - t:.0f} s")
    t = time.time(); _log(f"{name}: extracting")
    wildppg.extract_windows(mat, cache=True)
    problems = check_outputs(mat)
    if problems:
        for p in wildppg.cache_paths(mat): p.unlink(missing_ok=True)
        _log(f"{name}: CHECK FAILED ({'; '.join(problems)}); raw file kept, outputs removed"); return "failed"
    _log(f"{name}: extracted and checked in {time.time() - t:.0f} s")
    if not keep_raw:
        mat.unlink(); _log(f"{name}: raw file deleted")
    return "done"

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--list", action="store_true", help="show the share's files and local status, download nothing")
    ap.add_argument("--only", action="append", default=[], help="participant id (e.g. e61); repeatable")
    ap.add_argument("--keep-raw", action="store_true", help="keep the raw .mat files after a successful check")
    a = ap.parse_args(argv)
    remote = list_remote()
    if a.only:
        wanted = {f"WildPPG_Part_{i}.mat" for i in a.only}
        unknown = wanted - set(remote)
        if unknown: ap.error(f"not on the share: {sorted(unknown)}")
        remote = {k: v for k, v in remote.items() if k in wanted}
    if a.list:
        for n, s in remote.items(): print(f"{n:28s} {s / 2**30:5.2f} GB  {'done' if is_done(n) else 'to do'}")
        return 0
    wildppg.DATA_DIR.mkdir(parents=True, exist_ok=True)
    results = {}
    for n, s in remote.items():
        try:
            results[n] = process(n, s, a.keep_raw)
        except Exception as err:
            _log(f"{n}: ERROR {type(err).__name__}: {err}"); results[n] = "failed"
            if "disk space" in str(err): break
    _log("summary: " + ", ".join(f"{k}={sum(v == k for v in results.values())}" for k in ("done", "skipped", "failed")))
    return 1 if "failed" in results.values() else 0

if __name__ == "__main__":
    sys.exit(main())
