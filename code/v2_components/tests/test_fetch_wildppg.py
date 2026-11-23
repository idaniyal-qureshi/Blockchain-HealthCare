"""Tests for code/extensions/data_layer/fetch_wildppg.py (download -> extract -> check -> delete). No network, no neurokit2, no real
data: downloads and extraction are replaced by fakes that write files like the real ones."""
import pathlib, sys
import numpy as np, pandas as pd, pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "extensions" / "data_layer"))
import fetch_wildppg as F
import wildppg as W

L = W.FS * W.WIN_S
LISTING = """<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:">
 <d:response><d:href>/public.php/webdav/data/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat></d:response>
 <d:response><d:href>/public.php/webdav/data/WildPPG_Part_e61.mat</d:href><d:propstat><d:prop><d:getcontentlength>1116700000</d:getcontentlength></d:prop></d:propstat></d:response>
 <d:response><d:href>/public.php/webdav/data/WildPPG_Part_an0.mat</d:href><d:propstat><d:prop><d:getcontentlength>1114500000</d:getcontentlength></d:prop></d:propstat></d:response>
 <d:response><d:href>/public.php/webdav/data/readme.txt</d:href><d:propstat><d:prop><d:getcontentlength>12</d:getcontentlength></d:prop></d:propstat></d:response>
</d:multistatus>"""

@pytest.fixture(autouse=True)
def _tmp_log(tmp_path, monkeypatch):
    monkeypatch.setattr(F, "LOG", tmp_path / "fetch_log.txt")       # never write to the real log

def _fake_extract(n_win=4000, ecg_frac=0.9, n_samples=None):
    """Replacement for wildppg.extract_windows that writes a plausible CSV + beat file next to the .mat."""
    def fake(mat, cache=True, **kw):
        rng = np.random.default_rng(0)
        df = pd.DataFrame({"window": np.arange(n_win), "t_s": np.arange(n_win) * 8.0})
        df["ecg_hr"] = np.where(rng.random(n_win) < ecg_frac, 70.0, np.nan)
        for loc in W.LOCATIONS: df[loc] = 72.0
        for loc in W.LOCATIONS: df[f"motion_{loc}"] = 0.01
        csv, npz = W.cache_paths(mat)
        W.save_beats(npz, {k: np.arange(0, n_win * L, 100) for k in ("ecg", *W.LOCATIONS)}, n_samples or n_win * L, "ppg_g")
        df[W.COLUMNS].to_csv(csv, index=False)
        return df
    return fake

def _fake_download(content=b"x" * 10):
    def fake(name, size, data_dir=W.DATA_DIR, retries=3):
        p = pathlib.Path(data_dir) / name; p.write_bytes(content); return p
    return fake

def test_parse_listing_keeps_participant_files_sorted():
    assert F.parse_listing(LISTING) == {"WildPPG_Part_an0.mat": 1114500000, "WildPPG_Part_e61.mat": 1116700000}

def test_success_deletes_raw_and_keeps_outputs(tmp_path, monkeypatch):
    monkeypatch.setattr(F, "download", _fake_download()); monkeypatch.setattr(W, "extract_windows", _fake_extract())
    assert F.process("WildPPG_Part_e61.mat", 10, data_dir=tmp_path) == "done"
    csv, npz = W.cache_paths(tmp_path / "WildPPG_Part_e61.mat")
    assert csv.exists() and npz.exists() and not (tmp_path / "WildPPG_Part_e61.mat").exists()
    assert F.is_done("WildPPG_Part_e61.mat", tmp_path)

def test_keep_raw_option(tmp_path, monkeypatch):
    monkeypatch.setattr(F, "download", _fake_download()); monkeypatch.setattr(W, "extract_windows", _fake_extract())
    assert F.process("WildPPG_Part_e61.mat", 10, keep_raw=True, data_dir=tmp_path) == "done"
    assert (tmp_path / "WildPPG_Part_e61.mat").exists()

def test_already_done_is_skipped_without_download(tmp_path, monkeypatch):
    monkeypatch.setattr(W, "extract_windows", _fake_extract()); _fake_extract()(tmp_path / "WildPPG_Part_e61.mat")
    monkeypatch.setattr(F, "download", lambda *a, **k: pytest.fail("must not download"))
    assert F.process("WildPPG_Part_e61.mat", 10, data_dir=tmp_path) == "skipped"

@pytest.mark.parametrize("bad", [dict(n_win=100), dict(ecg_frac=0.1), dict(n_samples=999 * L)])
def test_failed_check_keeps_raw_and_removes_outputs(tmp_path, monkeypatch, bad):
    monkeypatch.setattr(F, "download", _fake_download()); monkeypatch.setattr(W, "extract_windows", _fake_extract(**bad))
    assert F.process("WildPPG_Part_e61.mat", 10, data_dir=tmp_path) == "failed"
    assert (tmp_path / "WildPPG_Part_e61.mat").exists()                     # raw kept for inspection
    assert not any(p.exists() for p in W.cache_paths(tmp_path / "WildPPG_Part_e61.mat"))   # retried next run
    assert "CHECK FAILED" in F.LOG.read_text(encoding="utf-8")

def test_existing_raw_file_is_reused_not_redownloaded(tmp_path, monkeypatch):
    (tmp_path / "WildPPG_Part_e61.mat").write_bytes(b"x")                    # e.g. a run that stopped after downloading
    monkeypatch.setattr(F, "download", lambda *a, **k: pytest.fail("must not download"))
    monkeypatch.setattr(W, "extract_windows", _fake_extract())
    assert F.process("WildPPG_Part_e61.mat", 10, data_dir=tmp_path) == "done"

def test_refuses_when_disk_is_too_small(tmp_path, monkeypatch):
    monkeypatch.setattr(F.shutil, "disk_usage", lambda p: type("U", (), {"free": 2 ** 30})())
    monkeypatch.setattr(F, "download", lambda *a, **k: pytest.fail("must not download"))
    with pytest.raises(RuntimeError, match="disk space"):
        F.process("WildPPG_Part_e61.mat", 2 ** 30, data_dir=tmp_path)

def test_main_list_and_only(monkeypatch, capsys):
    monkeypatch.setattr(F, "list_remote", lambda: F.parse_listing(LISTING))
    assert F.main(["--list", "--only", "e61"]) == 0
    out = capsys.readouterr().out
    assert "WildPPG_Part_e61.mat" in out and "WildPPG_Part_an0.mat" not in out
    with pytest.raises(SystemExit):
        F.main(["--only", "zzz"])
