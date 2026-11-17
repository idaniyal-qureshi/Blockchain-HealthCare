"""
Extension benchmark: real ML-KEM vs the paper's mock vs RSA-2048.

    cd code/v2_components
    python benchmark_pqc.py              # full run, results in ./output/pqc
    python benchmark_pqc.py --quick      # small smoke run (seconds)
    python benchmark_pqc.py --no-pqc     # baseline schemes only, no liboqs needed

WHAT IT MEASURES (same methodology as the paper's Sec 5.4 / 5.6, extended)
  1. Primitive level  : KeyGen, Encaps / Decaps (RSA: OAEP transport of a 32-byte key), key and KEM-ciphertext sizes.
  2. Record level     : encrypt / decrypt of real sensor records (encryption.encrypt_record message format) for every scheme:
                        mean +- 95% CI (t, over runs), p50 / p95 / p99, throughput, envelope bytes, round-trip check.
  3. Memory           : growth of resident memory in a fresh process per scheme (Linux, /proc). tracemalloc cannot see liboqs' C memory.
  4. Environment      : CPU, OS, Python, library versions, git commit, seed -> output/pqc/environment.json.

METHOD
  * Each run builds fresh key pairs, then times every scheme in a random order (seeded); GC is off while timing; a warm-up is not timed.
  * Per-run means are aggregated across runs (CI over runs); pooled samples give the percentiles.
  * Results are laptop-class numbers. They are relative comparisons on one machine, not IoMT-device timings.
  * Close other programs, plug in the charger and use the performance CPU governor before a publishable run.
"""
import argparse
import datetime
import gc
import json
import os
import platform
import subprocess
import sys
import time

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import Crypto
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

import encryption as E
import sensors
from common import CFG, SEED, ci95

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.join(HERE, "output", "pqc")
FAMILY_CLASSICAL, FAMILY_MOCK, FAMILY_PQC = "classical", "paper mock (no real PQC)", "real ML-KEM"
FAMILY_COLORS = {FAMILY_CLASSICAL: "#888780", FAMILY_MOCK: "#BA7517", FAMILY_PQC: "#534AB7"}


# =====================================================================
# 1. WHICH SCHEMES
# =====================================================================

def scheme_factories(include_pqc=True):
    """name -> (family, function that builds a fresh scheme with new keys)."""
    f = {
        E.RSA_N:   (FAMILY_CLASSICAL, lambda: E.RSAScheme()),
        E.KY_N:    (FAMILY_MOCK, lambda: E.MockKyber(768, True)),
        E.K1024_N: (FAMILY_MOCK, lambda: E.MockKyber(1024, True)),
        E.RAW_N:   (FAMILY_MOCK, lambda: E.MockKyber(model_sizes=False)),
    }
    if include_pqc:
        import pqc_real
        for level in pqc_real.ML_KEM_SIZES:
            f[pqc_real.scheme_name(level)] = (FAMILY_PQC, (lambda lv=level: pqc_real.MLKEMHybrid(lv)))
    return f


# =====================================================================
# 2. TIMING HELPERS
# =====================================================================

def time_us(fn, items, warmup=30):
    """Time fn(item) for each item, in microseconds. Warm-up calls are not timed; GC is off while timing."""
    for i in range(min(warmup, len(items))):
        fn(items[i % len(items)])
    out = np.empty(len(items))
    was_on = gc.isenabled()
    gc.disable()
    try:
        pc = time.perf_counter_ns
        for i, item in enumerate(items):
            t0 = pc()
            fn(item)
            out[i] = (pc() - t0) / 1e3
    finally:
        if was_on:
            gc.enable()
    return out


def summarize(per_run):
    """per_run: one array of samples (us) per run. Mean +- CI is over the per-run means; percentiles use all samples."""
    run_means = np.array([a.mean() for a in per_run])
    pooled = np.concatenate(per_run)
    return dict(mean=float(run_means.mean()), ci95=float(ci95(run_means)), p50=float(np.percentile(pooled, 50)),
                p95=float(np.percentile(pooled, 95)), p99=float(np.percentile(pooled, 99)), n=int(pooled.size))


# =====================================================================
# 3. ENVIRONMENT
# =====================================================================

def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def _cpu_model():
    txt = _read("/proc/cpuinfo") or ""
    for line in txt.splitlines():
        if line.lower().startswith("model name"):
            return line.split(":", 1)[1].strip()
    return platform.processor() or None


def _git_commit():
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=HERE, capture_output=True, text=True, timeout=10).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def environment(include_pqc):
    info = dict(timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"), python=sys.version.split()[0],
                platform=platform.platform(), cpu_model=_cpu_model(), cpu_count=os.cpu_count(),
                cpu_governor=_read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"), pycryptodome=Crypto.__version__,
                numpy=np.__version__, seed=SEED, git_commit=_git_commit(), pqc=None)
    if include_pqc:
        import pqc_real
        info["pqc"] = pqc_real.library_info()
    return info


# =====================================================================
# 4. MEMORY (fresh process per scheme)
# =====================================================================

def _proc_kb(field):
    for line in (_read("/proc/self/status") or "").splitlines():
        if line.startswith(field):
            return int(line.split()[1])
    return None


def mem_worker(name, ops, include_pqc=True):
    """Runs in its own process: key generation + `ops` encrypt/decrypt calls; prints how much resident memory grew."""
    factory = scheme_factories(include_pqc)[name][1]
    msg = b"m" * 80
    gc.collect()
    try:
        with open("/proc/self/clear_refs", "w") as f:
            f.write("5")                                    # reset the peak-RSS counter (VmHWM) so it starts from "now"
    except OSError:
        pass
    base = _proc_kb("VmRSS")
    scheme = factory()
    for _ in range(ops):
        scheme.decrypt(scheme.encrypt(msg))
    peak, after = _proc_kb("VmHWM"), _proc_kb("VmRSS")
    print(json.dumps(dict(peak_growth_kb=None if None in (peak, base) else peak - base,
                          resident_growth_kb=None if None in (after, base) else after - base)))


def measure_memory(names, ops, repeats, include_pqc):
    out = {}
    for name in names:
        vals = []
        for _ in range(repeats):
            cmd = [sys.executable, os.path.abspath(__file__), "--mem-worker", name, "--mem-ops", str(ops)] + ([] if include_pqc else ["--no-pqc"])
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if r.returncode == 0 and r.stdout.strip():
                v = json.loads(r.stdout.strip().splitlines()[-1]).get("peak_growth_kb")
                if v is not None:
                    vals.append(v)
        out[name] = float(np.median(vals)) if vals else float("nan")
    return out


# =====================================================================
# 5. THE BENCHMARK
# =====================================================================

def primitive_samples(include_pqc, n, rsa_keygen_n):
    """One run of primitive-level timings. Returns {(scheme, op): samples_us} and a size table."""
    out, sizes = {}, {}
    rng_items = list(range(n))

    key = RSA.generate(2048)
    oaep_pub, oaep_priv = PKCS1_OAEP.new(key.publickey()), PKCS1_OAEP.new(key)
    k32 = get_random_bytes(32)
    ct = oaep_pub.encrypt(k32)
    out[(E.RSA_N, "keygen")] = time_us(lambda _: RSA.generate(2048), list(range(rsa_keygen_n)), warmup=0)
    out[(E.RSA_N, "encaps")] = time_us(lambda _: oaep_pub.encrypt(k32), rng_items)
    out[(E.RSA_N, "decaps")] = time_us(lambda _: oaep_priv.decrypt(ct), rng_items)
    sizes[E.RSA_N] = dict(public_key_bytes=len(key.publickey().export_key("DER")), kem_ct_bytes=len(ct))

    for level, name in ((768, E.KY_N), (1024, E.K1024_N)):
        m = E.MockKyber(level, True)
        kem_part, _ = m.encaps()
        out[(name, "keygen")] = time_us(lambda _: E.MockKyber(level, True), rng_items)
        out[(name, "encaps")] = time_us(lambda _: m.encaps(), rng_items)
        out[(name, "decaps")] = time_us(lambda _: m.decaps(kem_part), rng_items)
        sizes[name] = dict(public_key_bytes=len(m.public_key), kem_ct_bytes=len(kem_part))

    if include_pqc:
        import pqc_real
        for level in pqc_real.ML_KEM_SIZES:
            name = pqc_real.scheme_name(level)
            kp = pqc_real.MLKEMKeyPair(level)
            kem_ct, _ = pqc_real.encaps(level, kp.public_key)
            out[(name, "keygen")] = time_us(lambda _: pqc_real.MLKEMKeyPair(level), rng_items)
            out[(name, "encaps")] = time_us(lambda _: pqc_real.encaps(level, kp.public_key), rng_items)
            out[(name, "decaps")] = time_us(lambda _: kp.decaps(kem_ct), rng_items)
            sizes[name] = dict(public_key_bytes=len(kp.public_key), kem_ct_bytes=len(kem_ct))
    return out, sizes


def run(out_dir=DEFAULT_OUT, n_patients=5, n_steps=200, runs=None, prim_n=300, rsa_keygen_n=10, mem_repeats=3, mem_ops=500,
        include_pqc=True, measure_mem=True, verbose=True):
    runs = runs or CFG["N_RUNS"]
    os.makedirs(out_dir, exist_ok=True)
    say = print if verbose else (lambda *a, **k: None)
    factories = scheme_factories(include_pqc)
    names = list(factories)

    records = sensors.edge_records(n_patients=n_patients, n_steps=n_steps)
    messages = [E.record_to_bytes(r) for recs in records.values() for r in recs]
    plain_bytes = float(np.mean([len(m) for m in messages]))
    say(f"{len(messages)} sensor records (mean {plain_bytes:.0f} B), {len(names)} schemes, {runs} runs")

    env = environment(include_pqc)
    with open(os.path.join(out_dir, "environment.json"), "w") as f:
        json.dump(env, f, indent=2)

    rng = np.random.default_rng(SEED)
    enc_runs = {n: [] for n in names}
    dec_runs = {n: [] for n in names}
    sizes_rec = {}
    roundtrip_ok = {n: True for n in names}
    prim_runs, prim_sizes = {}, {}

    for run_i in range(runs):
        say(f"run {run_i + 1}/{runs}: fresh keys, random scheme order")
        schemes = {n: factories[n][1]() for n in names}
        for name in (names[i] for i in rng.permutation(len(names))):
            s = schemes[name]
            for m in messages[:10]:
                s.decrypt(s.encrypt(m))
            cts = [None] * len(messages)
            enc = np.empty(len(messages))
            was_on = gc.isenabled()
            gc.disable()
            try:
                pc = time.perf_counter_ns
                for i, m in enumerate(messages):
                    t0 = pc()
                    c = s.encrypt(m)
                    enc[i] = (pc() - t0) / 1e3
                    cts[i] = c
                dec = np.empty(len(messages))
                outs = [None] * len(messages)
                for i, c in enumerate(cts):
                    t0 = pc()
                    o = s.decrypt(c)
                    dec[i] = (pc() - t0) / 1e3
                    outs[i] = o
            finally:
                if was_on:
                    gc.enable()
            roundtrip_ok[name] &= all(o == m for o, m in zip(outs, messages))
            enc_runs[name].append(enc)
            dec_runs[name].append(dec)
            sizes_rec[name] = float(np.mean([len(c) for c in cts]))
        samples, sz = primitive_samples(include_pqc, prim_n, rsa_keygen_n)
        for k, v in samples.items():
            prim_runs.setdefault(k, []).append(v)
        prim_sizes = sz

    mem = measure_memory(names, mem_ops, mem_repeats, include_pqc) if measure_mem else {}

    rsa_enc, rsa_dec = summarize(enc_runs[E.RSA_N])["mean"], summarize(dec_runs[E.RSA_N])["mean"]
    rows = []
    for name in names:
        e, d = summarize(enc_runs[name]), summarize(dec_runs[name])
        rows.append(dict(scheme=name, family=factories[name][0], samples_per_run=len(messages), runs=runs,
                         enc_us=e["mean"], enc_ci95_us=e["ci95"], enc_p50_us=e["p50"], enc_p95_us=e["p95"], enc_p99_us=e["p99"],
                         dec_us=d["mean"], dec_ci95_us=d["ci95"], dec_p50_us=d["p50"], dec_p95_us=d["p95"], dec_p99_us=d["p99"],
                         enc_per_s=1e6 / e["mean"], dec_per_s=1e6 / d["mean"],
                         record_bytes=sizes_rec[name], overhead_bytes=sizes_rec[name] - plain_bytes,
                         size_vs_rsa=sizes_rec[name] / sizes_rec[E.RSA_N], enc_vs_rsa=e["mean"] / rsa_enc, dec_vs_rsa=d["mean"] / rsa_dec,
                         peak_rss_growth_kb=mem.get(name, float("nan")), roundtrip_ok=roundtrip_ok[name]))
    rec_df = pd.DataFrame(rows)

    prows = []
    for (name, op), arrs in prim_runs.items():
        s = summarize(arrs)
        prows.append(dict(scheme=name, family=factories[name][0], op=op, us=s["mean"], ci95_us=s["ci95"], p50_us=s["p50"], p95_us=s["p95"],
                          n=s["n"], **prim_sizes[name]))
    prim_df = pd.DataFrame(prows)

    rec_df.to_csv(os.path.join(out_dir, "records.csv"), index=False)
    prim_df.to_csv(os.path.join(out_dir, "primitives.csv"), index=False)
    plot(rec_df, os.path.join(out_dir, "fig_pqc_comparison.png"))
    say("\nRecord level (mean +- 95% CI over runs, microseconds):")
    say(rec_df[["scheme", "enc_us", "enc_ci95_us", "dec_us", "dec_ci95_us", "enc_per_s", "record_bytes", "size_vs_rsa", "roundtrip_ok"]]
        .round(2).to_string(index=False))
    say("\nPrimitive level (microseconds):")
    say(prim_df[["scheme", "op", "us", "ci95_us", "public_key_bytes", "kem_ct_bytes"]].round(2).to_string(index=False))
    say(f"\nSaved to {out_dir}")
    return dict(records=rec_df, primitives=prim_df, environment=env)


# =====================================================================
# 6. FIGURE
# =====================================================================

def plot(rec_df, path):
    plt.switch_backend("Agg")
    labels = [n.replace("Kyber-inspired mock", "Mock").replace(" (liboqs)", "").replace(" sizes", "") for n in rec_df.scheme]
    colors = [FAMILY_COLORS[f] for f in rec_df.family]
    x = np.arange(len(rec_df))
    fig, axs = plt.subplots(1, 3, figsize=(13, 4.2))
    panels = [("enc_us", "enc_ci95_us", "Encrypt time per record (us, log scale)", True), ("dec_us", "dec_ci95_us", "Decrypt time per record (us, log scale)", True),
              ("record_bytes", None, "Encrypted record size (bytes)", False)]
    for ax, (col, err, title, log) in zip(axs, panels):
        ax.bar(x, rec_df[col], yerr=None if err is None else rec_df[err], color=colors, capsize=2)
        if log:
            ax.set_yscale("log")
        ax.set_title(title, fontsize=10)
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=7)
        ax.grid(axis="y", alpha=0.3)
    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for c in FAMILY_COLORS.values()]
    axs[0].legend(handles, FAMILY_COLORS.keys(), fontsize=7)
    fig.suptitle("RSA-2048 vs the paper's mock vs real ML-KEM (error bars: 95% CI over runs)", fontsize=11)
    plt.tight_layout()
    plt.savefig(path, bbox_inches="tight")
    plt.close(fig)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true", help="small smoke run")
    ap.add_argument("--no-pqc", action="store_true", help="skip real ML-KEM (no liboqs needed)")
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--runs", type=int, default=None)
    ap.add_argument("--no-mem", action="store_true", help="skip the per-process memory measurement")
    ap.add_argument("--mem-worker", help=argparse.SUPPRESS)
    ap.add_argument("--mem-ops", type=int, default=500, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if a.mem_worker:
        mem_worker(a.mem_worker, a.mem_ops, include_pqc=not a.no_pqc)
        return
    if a.quick:
        run(a.out, n_patients=2, n_steps=20, runs=a.runs or 2, prim_n=50, rsa_keygen_n=2, mem_repeats=1, mem_ops=100,
            include_pqc=not a.no_pqc, measure_mem=not a.no_mem)
    else:
        run(a.out, runs=a.runs, include_pqc=not a.no_pqc, measure_mem=not a.no_mem)


if __name__ == "__main__":
    main()
