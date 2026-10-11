"""Runs every component in the same order as hospital_blockchain_paper_impl_v2.ipynb.

    cd code/v2_components
    python main.py              # figures are saved to ./output, no windows
    python main.py --show       # also open each figure in a window

About 7-10 minutes (most of it is the sensor authentication and the 1000-node simulations).
"""
import os, sys, warnings

def main(show=False):
    import matplotlib
    if not show and "ipykernel" not in sys.modules:
        matplotlib.use("Agg")                                               # plt.show() becomes a no-op; PNGs are still saved
        warnings.filterwarnings("ignore", message=".*non-interactive.*")    # ...and would otherwise warn on every figure
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
    os.makedirs(out, exist_ok=True); os.chdir(out)                          # every fig*.png lands in ./output

    import sensors, encryption, access_control, consensus, blockchain, report
    print("\n=== 1. Fault-tolerant sensor ingestion ==="); sen = sensors.run()
    print("\n=== 2. Encryption layer ===");                 enc = encryption.run()
    print("\n=== 3. Access control ===");                   access_control.run_checks(); access_control.run(enc["ky_r"])
    print("\n=== 4. Consensus ===");                        consensus.run_availability(); con = consensus.run()
    print("\n=== 5. Blockchain layer, end-to-end, storage, energy ===")
    blockchain.run(sen["PIPE"], enc["rsa_r"], enc["ky_r"], con["g"])
    print("\n=== Paper's reported values vs. this run ==="); report.run()


if __name__ == "__main__":
    main(show="--show" in sys.argv)
