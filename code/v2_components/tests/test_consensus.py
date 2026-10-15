"""Unit tests for consensus.py  (Hao et al. 2025: Sec 4.4, Algorithm 5, Eq 11, Lemma 2, Sec 6.2-6.4)

Run from the folder that holds consensus.py:
    python -m unittest test_consensus -v

Three kinds of test:
  * paper requirements  - each test names the section / equation it checks
  * maths checks        - the fast vectorised code is compared with a slow, obviously-correct version
  * KNOWN ISSUE tests   - marked @expectedFailure. They describe what the paper requires but the code does not do yet.
                          When the issue is fixed, unittest reports "unexpected success": remove the decorator then.
"""
import unittest
import numpy as np
import consensus as C
from common import CFG


def serial_loop(arrivals, costs, free_at):
    """Reference single-CPU queue written the slow, obvious way: c_k = max(a_k, c_(k-1)) + p_k."""
    t, out = free_at, []
    for a, p in zip(sorted(arrivals), costs):
        t = max(a, t) + p
        out.append(t)
    return out


def mean_latency(proto, n, rounds=5, mode="normal", seed=1):
    cl = C.ConsensusCluster(proto, n, seed=seed, mode=mode)
    return float(np.mean([cl.run_round()["latency"] for _ in range(rounds)]))


class TestQueueModel(unittest.TestCase):
    """The timing building blocks: _serial (one CPU working through a queue) and _cpu (per-message jitter)."""

    def test_serial_matches_plain_loop(self):
        rng = np.random.default_rng(0)
        for _ in range(500):
            n = int(rng.integers(1, 15))
            a = rng.uniform(0, 5, n)
            a[rng.random(n) < 0.2] = np.inf                     # some messages never arrive (crashed senders)
            p = rng.uniform(0.01, 1, n)
            free = rng.uniform(0, 3)
            np.testing.assert_allclose(C._serial(a, p, free), serial_loop(a, p, free))

    def test_serial_worked_example(self):
        # arrivals 5, 6, 20; cost 3 each; CPU free from 0  ->  finishes at 8, 11 (waited for msg 1), 23 (idle until 20)
        np.testing.assert_allclose(C._serial(np.array([5.0, 6.0, 20.0]), np.array([3.0, 3.0, 3.0]), 0.0), [8, 11, 23])

    def test_serial_respects_busy_cpu(self):
        # CPU busy sending until t=10: nothing can be processed before then
        self.assertGreaterEqual(C._serial(np.array([1.0, 2.0]), np.array([1.0, 1.0]), 10.0)[0], 11.0)

    def test_cpu_jitter_is_mean_preserving_and_positive(self):
        x = C._cpu(np.random.default_rng(1), 0.04, 200_000)
        self.assertAlmostEqual(x.mean(), 0.04, delta=0.0005)
        self.assertAlmostEqual(x.std() / x.mean(), CFG["JITTER_CV"], delta=0.01)
        self.assertTrue((x > 0).all())


class TestQuorum(unittest.TestCase):
    """Eq 11: Raft commits with floor(N/2)+1 accepts.  BFT baselines: 2f+1 with f = floor((N-1)/3)."""

    def test_raft_quorum_is_eq11(self):
        for n in [1, 2, 3, 4, 5, 7, 9, 10, 20, 100, 1000]:
            self.assertEqual(C.ConsensusCluster("Raft", n).quorum, n // 2 + 1, f"N={n}")

    def test_bft_quorum_is_2f_plus_1(self):
        for n, q in [(4, 3), (10, 7), (20, 13), (1000, 667)]:
            for proto in ["PBFT", "HotStuff", "Tendermint"]:
                self.assertEqual(C.ConsensusCluster(proto, n).quorum, q, f"{proto} N={n}")


class TestAvailability(unittest.TestCase):
    """Algorithm 5 lines 7-10 and Lemma 2: commit if enough healthy nodes remain, otherwise return NULL."""

    def test_commits_exactly_when_enough_nodes_alive(self):
        for proto in ["Raft", "PBFT", "HotStuff", "Tendermint"]:
            for n in [4, 7, 10, 21]:
                for k in range(n):
                    c = C.ConsensusCluster(proto, n, seed=k)
                    c.crash(k)
                    r = c.run_round()
                    self.assertEqual(r["committed"], n - k >= c.quorum, f"{proto} N={n} crashed={k}")
                    if not r["committed"]:
                        self.assertTrue(np.isnan(r["latency"]))

    def test_lemma2_at_1000_nodes(self):
        for crashed, expect in [(499, True), (500, False)]:
            c = C.ConsensusCluster("Raft", 1000, seed=1)
            c.crash(crashed)
            self.assertEqual(c.run_round()["committed"], expect, f"crashed={crashed}")

    def test_crash_marks_exact_number_of_nodes(self):
        c = C.ConsensusCluster("Raft", 50, seed=4)
        c.crash(10)
        c.crash(5)
        self.assertEqual(int((~c.alive).sum()), 15)


class TestLeader(unittest.TestCase):
    """Algorithm 5 line 1 / Sec 3.1: leader L ~ U(N \\ F), chosen again every round."""

    def test_leader_is_never_a_crashed_node(self):
        c = C.ConsensusCluster("Raft", 15, seed=3)
        c.crash(7)
        for _ in range(200):
            r = c.run_round()
            self.assertTrue(c.alive[r["leader"]])

    def test_leader_rotates_across_all_healthy_nodes(self):
        c = C.ConsensusCluster("Raft", 10, seed=0)
        self.assertEqual(len({c.run_round()["leader"] for _ in range(300)}), 10)

    def test_term_increases_every_round(self):
        c = C.ConsensusCluster("Raft", 7, seed=0)
        for t in range(1, 6):
            c.run_round()
            self.assertEqual(c.term, t)


class TestMessageComplexity(unittest.TestCase):
    """Sec 4.4: Raft needs O(N) messages, PBFT O(N^2). Exact counts for this simulator's message patterns."""

    def test_exact_message_counts(self):
        for n in [4, 10, 20, 50]:
            def msgs(p):
                return C.ConsensusCluster(p, n, seed=1).run_round()["msgs"]
            self.assertEqual(msgs("Raft"), 2 * (n - 1))                          # AppendEntries + acks
            self.assertEqual(msgs("PBFT"), (n - 1) + 2 * n * (n - 1))            # pre-prepare + 2 all-to-all phases
            self.assertEqual(msgs("Tendermint"), (n - 1) + 2 * n * (n - 1))      # proposal + prevote + precommit
            self.assertEqual(msgs("HotStuff"), 7 * (n - 1))                      # 3 leader round trips + decide

    def test_crashed_nodes_send_no_replies(self):
        c = C.ConsensusCluster("Raft", 20, seed=1)
        c.crash(5)
        self.assertEqual(c.run_round()["msgs"], 19 + 14)                         # 19 sent, 14 live followers reply

    def test_raft_linear_pbft_quadratic(self):
        raft = [C.ConsensusCluster("Raft", n, seed=1).run_round()["msgs"] for n in (10, 100)]
        pbft = [C.ConsensusCluster("PBFT", n, seed=1).run_round()["msgs"] for n in (10, 100)]
        self.assertAlmostEqual(raft[1] / raft[0], 11, delta=1)                   # 10x nodes -> ~10x messages
        self.assertGreater(pbft[1] / pbft[0], 90)                                # 10x nodes -> ~100x messages


class TestModesAndTiming(unittest.TestCase):
    """Sec 6.2 modes (normal / failover / congestion) and basic timing sanity."""

    def test_latency_at_least_one_round_trip(self):
        r = C.ConsensusCluster("Raft", 10, seed=1).run_round()
        self.assertGreater(r["latency"], 2 * CFG["HOP_DELAY_MS"])

    def test_failover_elects_every_10_rounds(self):
        c = C.ConsensusCluster("Raft", 20, seed=2, mode="failover")
        low = CFG["ELECTION_TIMEOUT_MS"][0]
        for i in range(30):
            lat = c.run_round()["latency"]
            if i % CFG["FAILOVER_EVERY"] == 0:
                self.assertGreaterEqual(lat, low, f"round {i} should include an election")
            else:
                self.assertLess(lat, low, f"round {i} should not include an election")

    def test_congestion_adds_the_extra_hop_delay(self):
        extra = mean_latency("Raft", 20, mode="congestion") - mean_latency("Raft", 20)
        expected = 2 * (CFG["CONGESTION_FACTOR"] - 1) * CFG["HOP_DELAY_MS"]     # two hops per round trip
        self.assertAlmostEqual(extra, expected, delta=0.5)

    def test_raft_faster_than_pbft_at_20_nodes(self):
        self.assertLess(mean_latency("Raft", 20), mean_latency("PBFT", 20))

    def test_raft_scales_near_linearly(self):                                  # Sec 6.4 / Fig 6: "near-linear"
        lat = {n: mean_latency("Raft", n) for n in (200, 600, 1000)}
        s1, s2 = (lat[600] - lat[200]) / 400, (lat[1000] - lat[600]) / 400
        self.assertAlmostEqual(s1, s2, delta=0.2 * s1)

    def test_same_seed_gives_same_results(self):
        a = [C.ConsensusCluster("PBFT", 10, seed=9).run_round()["latency"] for _ in range(3)]
        b = [C.ConsensusCluster("PBFT", 10, seed=9).run_round()["latency"] for _ in range(3)]
        self.assertEqual(a, b)


class TestValidateHook(unittest.TestCase):
    """run_round(validate=...) lets honest nodes reject a block (used by blockchain.py for a compromised leader)."""

    def test_rejected_block_is_not_committed_and_log_is_truncated(self):
        c = C.ConsensusCluster("Raft", 7, seed=0)
        r = c.run_round(validate=lambda leader: False)
        self.assertFalse(r["committed"])
        self.assertEqual(c.commit_index, 0)
        self.assertTrue((c.log_len == 0).all())

    def test_accepted_block_is_committed_and_appended(self):
        c = C.ConsensusCluster("Raft", 7, seed=0)
        c.crash(2)
        r = c.run_round(validate=lambda leader: True)
        self.assertTrue(r["committed"])
        self.assertEqual(c.commit_index, 1)
        self.assertTrue((c.log_len[c.alive] == 1).all())
        self.assertTrue((c.log_len[~c.alive] == 0).all())                       # crashed nodes do not append

    def test_validate_receives_the_leader(self):
        c = C.ConsensusCluster("Raft", 7, seed=0)
        seen = []
        r = c.run_round(validate=lambda leader: seen.append(leader) or True)
        self.assertEqual(seen, [r["leader"]])


class TestAgainstPaperNumbers(unittest.TestCase):
    """KNOWN ISSUE: the CPU-cost constants in common.py are assumptions; with them Raft is ~3x faster than the paper reports.
    Setting SEND_COST_MS = 0.04 and PROC_COST_MS = 0.12 makes these pass (tested)."""

    @unittest.expectedFailure
    def test_raft_1000_nodes_about_100ms(self):                                # Fig 6 (~100 ms), Sec 6.2 (<115 ms)
        self.assertTrue(80 <= mean_latency("Raft", 1000) <= 120)

    @unittest.expectedFailure
    def test_raft_slope_about_0_1_ms_per_node(self):                           # Sec 6.4
        slope = (mean_latency("Raft", 1000) - mean_latency("Raft", 200)) / 800
        self.assertTrue(0.08 <= slope <= 0.12)


if __name__ == "__main__":
    unittest.main(verbosity=2)
