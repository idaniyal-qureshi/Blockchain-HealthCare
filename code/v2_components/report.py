"""Paper's reported values vs. this run.

Reads RESULTS after every other part has run (see main.py). Assumptions and the paper's self-contradictions are listed in ASSUMPTIONS.md.
"""
import pandas as pd
from common import CFG, display, IN_NOTEBOOK, RESULTS


def run():
    R = RESULTS
    claims = pd.DataFrame([
        ("Encryption time reduction vs RSA-2048", "72.3% (abstract); 91.3% (Sec 6.5)", f"{R['enc_red']:.1f}%"),
        ("Decryption time reduction vs RSA-2048", "74.4% (abstract); 97.5% (Sec 6.5)", f"{R['dec_red']:.1f}%"),
        ("RSA-2048 enc / dec time", "0.8-2.2 ms / 46 µs (Sec 6.5); 5.60 / 3.65 ms (Fig 8)", f"{R['rsa_enc_us']:.0f} µs / {R['rsa_dec_us']:.0f} µs"),
        ("Kyber-inspired decryption time", "≈1.15 µs (Sec 6.5)", f"{R['ky_dec_us']:.1f} µs"),
        ("Record size, Kyber-inspired vs RSA (Sec 6.7 'memory usage')", "2400 vs 2800 B, −14.3% (Sec 6.7); 32 vs 256 B (Fig 8)",
         f"{R['ct_ky']:.0f} B (768 sizes) / {R['ct_raw']:.0f} B (raw) vs {R['ct_rsa']:.0f} B ({R['rec_red']:+.1f}% for 768 sizes)"),
        ("Python peak memory during encryption", "~14% lower (abstract)", f"{R['mem_red']:.1f}% lower"),
        ("Authorization verification time", "~0.002 ms (Sec 6.1); <0.4 ms (Sec 3.4/4.3)", f"{R['auth_ms']:.4f} ms"),
        ("RBAC check time", "0.0005 ms (Sec 6.1)", f"{R['rbac_ms']:.4f} ms"),
        ("Proof generation time", "<0.01 ms typical (Sec 6.6)", f"{R['proof_gen_ms']:.4f} ms"),
        ("Access-control false positives / negatives", "tracked, not reported (Sec 5.5)", f"{R['fp']:.2f}% / {R['fn']:.2f}%"),
        ("Raft latency @1000 nodes: normal / failover / congestion", "<115 / 145 / 125 ms (Sec 6.2); <200 ms (Sec 6.3); 145 ms (Sec 6.11)",
         f"{R['raft_1000']:.1f} / {R['raft_fo']:.1f} / {R['raft_cg']:.1f} ms"),
        ("Raft slope", "~0.1 ms per node (Sec 6.4)", f"{R['raft_slope']:.3f} ms/node"),
        ("HotStuff / Tendermint latency @1000", "165 / 158 ms (Sec 6.2); 140-160 ms (Sec 6.3)", f"{R['hs_1000']:.1f} / {R['tm_1000']:.1f} ms"),
        ("PBFT latency @1000 nodes", ">2000 ms (Sec 6.2); >2100 ms (Sec 6.3); 1200 ms (Fig 5)",
         f"{R['pbft_1000']:.1f} ms extrapolated" + (f"; {R['pbft_sim_1000']:.1f} ms simulated" if CFG['PBFT_FULL_SCALE'] else "")),
        ("Consensus latency reduction vs PBFT", "92.3% (abstract)", f"{100 * (1 - R['raft_1000'] / R['pbft_1000']):.1f}% @1000 (PBFT extrapolated); {100 * (1 - R['raft_20'] / R['pbft_20']):.1f}% @20 (both simulated)"),
        ("Throughput @1000: Raft / PBFT / HotStuff / Tendermint", "1.26 M / 1.08 M / 1.18 M / 1.15 M TPS (Fig 12)",
         f"{R['raft_tps']:.0f} / {R['pbft_tps']:.0f} / {R['hs_tps']:.0f} / {R['tm_tps']:.0f} TPS (block = {CFG['BLOCK_SIZE']} tx)"),
        ("Raft / PBFT throughput ratio", "fivefold (abstract)", f"{R['raft_tps'] / R['pbft_tps']:.2f}x"),
        ("3-of-5 median accuracy at 5 / 10 / 20 / 30% faults", "100 / 99.5 / 98 / 96% (Fig 10); 89.4-93.2% (Sec 6.9)",
         " / ".join(f"{R[f'median_{r}']:.1f}" for r in (5, 10, 20, 30)) + "%"),
        ("Kalman accuracy across rates", "92.1-96.7% (Sec 6.9)", f"{min(R[f'kalman_{r}'] for r in (5, 10, 20, 30)):.1f}-{max(R[f'kalman_{r}'] for r in (5, 10, 20, 30)):.1f}%"),
        ("Kalman − median at 30% faults", "+6.8 points (Sec 6.9)", f"{R['kalman_30'] - R['median_30']:+.1f} points"),
        ("Mean smoothing vs Kalman at 20%", ">8 points lower (Sec 6.9)", f"{R['kalman_20'] - R['mean_20']:.1f} points lower"),
        ("No correction at 30% faults", "<75% (Sec 6.9)", f"{R['none_30']:.1f}%"),
        ("Energy reduction vs RSA + PBFT", "9.4-12.3% (Sec 4.6, abstract); 9.4% (Fig 13)", f"{R['energy']:.1f}%"),
        ("Ledger storage", "~15 MB/day (abstract)", f"{R['storage_mb_day']:,.0f} MB/day (1000 patients, 1 record / patient / min)"),
    ], columns=["Metric", "Paper", "This run"])
    if IN_NOTEBOOK: display(claims.style.hide(axis="index"))
    else: print(claims.to_string(index=False))                         # a Styler has no text form outside a notebook
    return claims


if __name__ == "__main__":
    print("report.py needs RESULTS from every other part; running main.py instead.")
    import main; main.main()
