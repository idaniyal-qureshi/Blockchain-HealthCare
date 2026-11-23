"""Smoke tests for benchmark_pqc.py: it runs end to end on a tiny workload and its output is internally consistent.
They do not check speed, only that the numbers are produced, round-trip checks pass and the sizes follow from the algorithms."""
import json
import os

import pytest

import benchmark_pqc as B
import encryption as E

try:
    import pqc_real
except (ImportError, RuntimeError, OSError):
    if os.environ.get("REQUIRE_PQC") == "1":
        raise
    pqc_real = None

TINY = dict(n_patients=1, n_steps=6, runs=2, prim_n=5, rsa_keygen_n=1, measure_mem=False, verbose=False)


@pytest.fixture(scope="module")
def result(tmp_path_factory):
    out = tmp_path_factory.mktemp("bench")
    return B.run(out_dir=str(out), include_pqc=pqc_real is not None, **TINY), out


def test_output_files_are_written(result):
    _, out = result
    for name in ("records.csv", "primitives.csv", "environment.json", "fig_pqc_comparison.png"):
        assert (out / name).stat().st_size > 0


def test_every_scheme_round_trips_and_is_timed(result):
    res, _ = result
    rec = res["records"]
    assert rec.roundtrip_ok.all()
    assert (rec[["enc_us", "dec_us", "enc_per_s", "dec_per_s"]] > 0).all().all()
    assert {E.RSA_N, E.KY_N, E.K1024_N, E.RAW_N} <= set(rec.scheme)


def test_hybrid_overhead_follows_from_the_algorithms(result):
    res, _ = result
    rec = res["records"].set_index("scheme")
    assert rec.loc[E.KY_N, "overhead_bytes"] == 1088 + 12 + 16
    assert rec.loc[E.RSA_N, "record_bytes"] == 256


@pytest.mark.skipif(pqc_real is None, reason="liboqs not installed")
def test_real_ml_kem_rows_and_environment(result):
    res, out = result
    rec = res["records"].set_index("scheme")
    for level, ct in ((512, 768), (768, 1088), (1024, 1568)):
        assert rec.loc[pqc_real.scheme_name(level), "overhead_bytes"] == ct + 12 + 16
    env = json.loads((out / "environment.json").read_text())
    assert env["pqc"]["liboqs"] and env["pqc"]["ML-KEM-768"]["spec"] == "FIPS203"
    prim = res["primitives"]
    assert {"keygen", "encaps", "decaps"} <= set(prim[prim.scheme == "ML-KEM-768 (liboqs)"].op)


def test_primitive_sizes_are_recorded(result):
    prim = result[0]["primitives"]
    rsa = prim[prim.scheme == E.RSA_N]
    assert (rsa.kem_ct_bytes == 256).all()


def test_memory_worker_runs_in_a_fresh_process():
    mem = B.measure_memory([E.RAW_N], ops=20, repeats=1, include_pqc=False)
    assert E.RAW_N in mem
