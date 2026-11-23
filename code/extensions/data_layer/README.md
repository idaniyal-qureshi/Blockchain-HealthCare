# Data layer: the paper's sensor correction on real data (WildPPG)

The base implementation (`code/v2_components/sensors.py`, Hao et al. 2025, Sec 4.1 / 5.2-5.3) tests its sensor-correction methods
on fully simulated data: an invented true heart rate x\*, five fake sensor readings around it, and injected faults. This extension
runs the **same base functions, unchanged**, on real recordings where both the sensor readings and a reference value are known.
The base code is not modified.

## Dataset

**WildPPG** (Meier, Demirel, Holz, *WildPPG: A Real-World PPG Dataset of Long Continuous Recordings*, NeurIPS 2024 Datasets and
Benchmarks, ETH Zürich; <https://siplab.org/projects/WildPPG>).

- 16 participants, about 13.5 h each, recorded outdoors during everyday life.
- 4 body-worn devices (forehead, sternum, wrist, ankle), each with a 3-colour optical heart sensor (PPG) at 128 Hz, plus motion,
  temperature and altitude. The sternum device also records a Lead-I ECG.
- Here: the 4 green PPG sensors are the 4 real redundant sensors; the ECG heart rate is the answer key x\*.

**Licence:** CC BY-NC-SA 4.0 per the authors' repository (the Hugging Face copy is labelled MIT). Academic, non-commercial use with
attribution. The data is **never committed or redistributed**: `data/` and `output/` are gitignored by this folder's `.gitignore`.

Each participant file is 1.1-1.4 GB (about 20 GB for all 16), from the public share
<https://polybox.ethz.ch/index.php/s/NWTuyNojU7aya1y> (`data/WildPPG_Part_<id>.mat`). To avoid keeping 20 GB on disk,
`fetch_wildppg.py` handles one participant at a time: download, extract, check, then delete the raw file. What stays is the
window table plus the detected beat times, about 1.7 MB per participant. Extraction is deterministic, so a re-download reproduces it.

## Files

| File | Role |
|---|---|
| `wildppg.py` | Loads a participant, turns raw ECG/PPG into one heart rate per 8-s window, caches the table as CSV |
| `fetch_wildppg.py` | Download -> extract -> check -> delete, one participant at a time (resumable; `--list`, `--only <id>`) |
| `run_wildppg.py` | Runs the paper's methods (base functions) on the 4 real sensors, grades them against the ECG, writes figures and `summary.md` |
| `../../v2_components/tests/test_wildppg.py`, `test_run_wildppg.py` | Tests; run in CI without the data or NeuroKit2 (beat-detection tests skip themselves) |

## Method in short

- **Windows:** non-overlapping 8 s. Heart rate = 60 / median inter-beat interval, beats limited to 35-185 bpm (paper Sec 3.3.1).
- **ECG answer key:** NeuroKit2 Pan-Tompkins R-peaks, plus a regularity rule (≥ 3 intervals, shortest/longest ≥ 0.75) that
  approximates the authors' cleaning.
- **PPG sensors:** NeuroKit2 `charlton` beat detector (MSPTDfast) on the negated signal, identical for all 4 locations. The ECG is
  used only to compare detectors, never to choose a reading in a window.
- **Methods:** single sensors, mean, majority voting (`mode_rounded`), median (`algorithm1`), Kalman (`agg_kalman`), Algorithm 2
  (`algorithm2` + `fault_estimate`), and a single-attempt Fig 2 pipeline (no HMAC, no retransmission: recorded data cannot be
  re-measured). All from `sensors.py`, unchanged.
- **Grading:** the paper's ±1 bpm (Eq 16), plus ±5 bpm, MAE, RMSE and coverage, overall and by activity level.
- **Exclusions:** sample ranges that the dataset's own notes mark as invalid are dropped for all sensors: an0 has a 15-s ankle gap, k2s a 53-min wrist gap and l38 a 27-min wrist gap.
- **Noisy ECG:** the notes say the ECG of fex, kjd and p5d is noisy. Their answer key covers only 28-34 % of windows, so they are
  left out of the main pooled result. `--include-noisy-ecg` adds them back.

## Running

Needs `neurokit2` in addition to `code/v2_components/requirements.txt`.

```bash
python code/extensions/data_layer/fetch_wildppg.py            # all participants, one at a time (about 20-30 min each)
python code/extensions/data_layer/run_wildppg.py $(for f in code/extensions/data_layer/data/wildppg/*_charlton.csv; do echo --from-csv $f; done)
python code/extensions/data_layer/run_wildppg.py --from-csv code/extensions/data_layer/data/wildppg/WildPPG_Part_an0_ppg_g_w8_charlton.csv
```

Outputs go to `output/wildppg/`: per participant `windows.csv`, `metrics.csv` and four figures, plus `summary.md`.

## Limitations

- 4 sensors instead of the paper's 5.
- Errors include beat-detection errors, not only sensor faults.
- The ECG reference approximates, but is not identical to, the authors' cleaned reference.
- ±1 bpm is very strict for optical sensors, so ±5 bpm and MAE are reported too.
- The base's Kalman and ε settings were tuned for the simulation's tiny noise and are deliberately left unchanged.
