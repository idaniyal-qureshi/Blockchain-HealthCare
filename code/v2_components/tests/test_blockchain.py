"""Unit tests for blockchain.py  (Hao et al. 2025: Eq 12, Sec 3.2, 4.3.2-4.3.3 audit trail, 4.5, 4.6 / Eq 13, 4.7 threat model)

Run from the folder that holds blockchain.py:
    python -m unittest test_blockchain -v

Three kinds of test:
  * ledger tests       - Block / Chain / SmartContractEngine on small hand-made chains
  * end-to-end tests   - run_pipeline() is run once; its internal objects (chain, cluster, contracts, cipher) are captured
                         and checked against what the paper requires
  * KNOWN ISSUE tests  - marked @expectedFailure; when the issue is fixed unittest reports "unexpected success":
                         remove the decorator then.
"""
import contextlib, io, json, os, re, tempfile, unittest
from unittest import mock
import numpy as np, pandas as pd
import matplotlib
matplotlib.use("Agg")
import blockchain as B
from access_control import PatientDevice
from common import CFG, RESULTS

RECORD_META_KEYS = ("pseud", "ts", "alert", "retx", "quarantined")


def make_chain(n_blocks=3):
    ch = B.Chain()
    for i in range(n_blocks):
        ch.append([os.urandom(50), os.urandom(60)], [os.urandom(32), os.urandom(32)], {"kind": "records", "i": i})
    return ch


class Pipeline:
    """Runs run_pipeline() once and keeps the objects it creates internally."""
    _res = None

    @classmethod
    def get(cls):
        if cls._res is None:
            got, buf = {}, io.StringIO()

            def spy(klass, key):
                orig = klass.__init__
                def init(self, *a, **k):
                    orig(self, *a, **k)
                    got[key] = self
                return mock.patch.object(klass, "__init__", init)

            with spy(B.Chain, "chain"), spy(B.SmartContractEngine, "contracts"), spy(B.MockKyberHybrid, "scheme"), \
                 spy(B.ConsensusCluster, "cluster"), contextlib.redirect_stdout(buf):
                got["result"] = B.run_pipeline()
            got["out"] = buf.getvalue()
            cls._res = got
        return cls._res


def blocks_of(kind):
    return [b for b in Pipeline.get()["chain"].blocks if b.metadata.get("kind") == kind]


# ------------------------------------------------------------------ ledger: Eq 12 and integrity
class TestBlockStructure(unittest.TestCase):
    """Eq 12: B_i = <H(B_i-1), {c_j}, {p_j}, timestamp, metadata>."""

    def test_genesis_block(self):
        g = B.Chain().blocks[0]
        self.assertEqual((g.index, g.prev_hash), (0, "0" * 64))
        self.assertEqual(g.hash, g.compute_hash())

    def test_block_has_eq12_fields_and_links_to_previous(self):
        ch = make_chain(2)
        for i in (1, 2):
            b = ch.blocks[i]
            self.assertEqual(b.index, i)
            self.assertEqual(b.prev_hash, ch.blocks[i - 1].hash)
            self.assertEqual(len(b.ciphertexts), 2)
            self.assertEqual(len(b.proofs), 2)
            self.assertIsInstance(b.timestamp, float)
            self.assertIn("kind", b.metadata)

    def test_hash_is_deterministic_sha256(self):
        b = make_chain(1).blocks[1]
        self.assertEqual(b.compute_hash(), b.compute_hash())
        self.assertRegex(b.hash, r"^[0-9a-f]{64}$")

    def test_nbytes_counts_every_part(self):
        b = make_chain(1).blocks[1]
        expected = 64 + 8 + 110 + 64 + len(json.dumps(b.metadata, default=str))
        self.assertEqual(b.nbytes(), expected)


class TestTamperDetection(unittest.TestCase):
    """Lemma 1 / Sec 4.5: any change to a stored block must make verify() fail."""

    def test_untouched_chain_verifies(self):
        self.assertTrue(make_chain().verify())

    def test_change_to_any_field_is_detected(self):
        changes = {
            "ciphertext": lambda b: setattr(b, "ciphertexts", [b"tampered"] + b.ciphertexts[1:]),
            "proof": lambda b: setattr(b, "proofs", [b"\x00" * 32] + b.proofs[1:]),
            "metadata": lambda b: b.metadata.update(i=999),
            "timestamp": lambda b: setattr(b, "timestamp", b.timestamp + 1),
            "index": lambda b: setattr(b, "index", 42),
        }
        for name, change in changes.items():
            ch = make_chain()
            change(ch.blocks[1])
            self.assertFalse(ch.verify(), f"change to {name} not detected")

    def test_recomputing_the_hash_breaks_the_next_link(self):
        ch = make_chain()
        ch.blocks[1].ciphertexts = [b"tampered"]
        ch.blocks[1].hash = ch.blocks[1].compute_hash()          # attacker "fixes" the hash
        self.assertFalse(ch.verify())                             # ...but block 2 still points to the old one

    def test_removed_or_reordered_blocks_are_detected(self):
        ch = make_chain()
        del ch.blocks[1]
        self.assertFalse(ch.verify())
        ch = make_chain()
        ch.blocks[1], ch.blocks[2] = ch.blocks[2], ch.blocks[1]
        self.assertFalse(ch.verify())

    def test_limitation_last_block_rewrite_needs_replicas(self):
        """Documents a property, not a bug: rewriting the NEWEST block and its hash cannot be detected by verify() alone.
        In the paper's design the replicated ledger on every hospital node is what protects the head of the chain."""
        ch = make_chain()
        ch.blocks[-1].ciphertexts = [b"tampered"]
        ch.blocks[-1].hash = ch.blocks[-1].compute_hash()
        self.assertTrue(ch.verify())


class TestSmartContractEngine(unittest.TestCase):
    """Fig 2 'Smart Contract Trigger Handler': rules run on every committed block."""

    def test_matching_rules_emit_events(self):
        eng = B.SmartContractEngine()
        eng.register("big", lambda tx: tx.get("v", 0) > 10)
        eng.register("odd", lambda tx: tx.get("v", 0) % 2 == 1)
        blk = B.Block(5, "x", [], [], 0.0, {"tx": [{"v": 11, "pseud": "a"}, {"v": 2, "pseud": "b"}, {"v": 3, "pseud": "c"}]})
        eng.on_commit(blk)
        self.assertEqual(sorted((e["rule"], e["who"]) for e in eng.events), [("big", "a"), ("odd", "a"), ("odd", "c")])
        self.assertTrue(all(e["block"] == 5 for e in eng.events))

    def test_block_without_transactions_emits_nothing(self):
        eng = B.SmartContractEngine()
        eng.register("any", lambda tx: True)
        eng.on_commit(B.Block(1, "x", [], [], 0.0, {"genesis": True}))
        self.assertEqual(eng.events, [])


class TestGatewayTag(unittest.TestCase):
    """Data packaging: the gateway tags (ciphertext, proof, metadata) so validators can detect changes (threat A1)."""

    def test_tag_changes_with_any_input(self):
        ct, p, meta = b"ciphertext", b"proof", {"pseud": "x", "alert": False}
        t = B.tx_tag(ct, p, meta)
        self.assertNotEqual(t, B.tx_tag(b"Ciphertext", p, meta))
        self.assertNotEqual(t, B.tx_tag(ct, b"Proof", meta))
        self.assertNotEqual(t, B.tx_tag(ct, p, {"pseud": "x", "alert": True}))

    def test_tag_ignores_key_order(self):
        self.assertEqual(B.tx_tag(b"c", b"p", {"a": 1, "b": 2}), B.tx_tag(b"c", b"p", {"b": 2, "a": 1}))


# ------------------------------------------------------------------ end-to-end: run_pipeline()
class TestPipelineConsensus(unittest.TestCase):
    """Sec 3.2 steps 5-6 and threat A1: blocks go through Raft with a crashed and a compromised node."""

    def test_cluster_setup(self):
        c = Pipeline.get()["cluster"]
        self.assertEqual(c.proto, "Raft")
        self.assertEqual(int(c.alive.sum()), 6)                                    # 7 nodes, 1 crashed
        self.assertEqual(len(c.compromised), 1)
        self.assertTrue(all(c.alive[i] for i in c.compromised))                    # compromised node is a live one

    def test_every_block_went_through_consensus(self):
        res = Pipeline.get()
        self.assertEqual(res["cluster"].commit_index, len(res["chain"].blocks) - 1)
        terms = [b.metadata["term"] for b in res["chain"].blocks[1:]]
        self.assertEqual(terms, sorted(set(terms)))                                # strictly increasing terms

    def test_compromised_leader_was_rejected_and_no_tampered_record_committed(self):
        rejected = int(re.search(r"tampered with them: (\d+)", Pipeline.get()["out"]).group(1))
        self.assertGreaterEqual(rejected, 1)
        for b in blocks_of("records"):
            for ct, p, tx in zip(b.ciphertexts, b.proofs, b.metadata["tx"]):
                meta = {k: tx[k] for k in RECORD_META_KEYS}
                self.assertEqual(tx["tag"], B.tx_tag(ct, p, meta), "a record on the ledger fails its gateway tag")

    def test_chain_valid_before_tamper_demo_and_invalid_after(self):
        out = Pipeline.get()["out"]
        self.assertIn("chain valid = True", out)
        self.assertIn("after tampering with a stored record: False", out)


class TestPipelineRecords(unittest.TestCase):
    """Eq 12 contents on the real run: encrypted records + proofs, 10 per block, decryptable, no identities."""

    def test_four_record_blocks_of_ten(self):
        rec = blocks_of("records")
        self.assertEqual(len(rec), 4)
        for b in rec:
            self.assertEqual(len(b.ciphertexts), 10)
            self.assertEqual(len(b.proofs), 10)
            self.assertEqual(len(b.metadata["tx"]), 10)

    def test_records_decrypt_to_the_right_pseudonym(self):
        scheme = Pipeline.get()["scheme"]
        for b in blocks_of("records"):
            for ct, tx in zip(b.ciphertexts, b.metadata["tx"]):
                rec = json.loads(scheme.decrypt(ct))
                self.assertEqual(rec["pid"], tx["pseud"])
                self.assertEqual(len(rec["hr"]), 20)

    def test_no_patient_identity_on_the_ledger(self):                             # Sec 4.5, 3.1
        res = Pipeline.get()
        for b in res["chain"].blocks:
            self.assertNotIn("patient-", json.dumps(b.metadata, default=str))
        for b in blocks_of("records"):
            for ct in b.ciphertexts:
                self.assertNotIn(b"patient-", res["scheme"].decrypt(ct))

    def test_internal_fields_are_not_stored(self):
        for b in blocks_of("records"):
            for tx in b.metadata["tx"]:
                self.assertNotIn("p_bytes", tx)
                self.assertNotIn("meta", tx)


class TestPipelineAccessAndAudit(unittest.TestCase):
    """Sec 3.2 step 7 (access only if proof AND consensus succeed), Sec 4.3.2-4.3.3 (every decision logged on-chain)."""

    def test_access_outcomes(self):
        lines = {l.split("->")[0].strip(): l.split("->")[1].strip() for l in Pipeline.get()["out"].splitlines() if "->" in l}
        self.assertIn('"pid"', lines["Valid proof + policy"])
        self.assertIn('"pid"', lines["Valid, 2 corrupted transmissions"])
        self.assertEqual(lines["Wrong secret (other hospital)"], "DENIED")
        self.assertEqual(lines["Valid proof, write not permitted"], "DENIED")
        self.assertEqual(lines["After policy revocation"], "DENIED")

    def test_all_decision_types_are_on_chain(self):
        events = {tx["event"] for b in blocks_of("audit") for tx in b.metadata["tx"]}
        for ev in ["grant", "policy_define", "allow", "deny", "policy_allow", "policy_deny", "policy_revoke"]:
            self.assertIn(ev, events)

    def test_critical_vitals_alert_for_tachycardic_patient(self):
        alerts = {e["who"] for e in Pipeline.get()["contracts"].events if e["rule"] == "critical-vitals alert"}
        self.assertEqual(alerts, {PatientDevice("patient-0005").pseud})

    def test_maintenance_rule_matches_record_metadata(self):
        expected = {tx["pseud"] for b in blocks_of("records") for tx in b.metadata["tx"] if tx["retx"] >= 2 or tx["quarantined"] > 0}
        fired = {e["who"] for e in Pipeline.get()["contracts"].events if e["rule"] == "sensor maintenance"}
        self.assertEqual(fired, expected)

    @unittest.expectedFailure
    def test_access_audit_rule_covers_every_decision(self):
        """KNOWN ISSUE: the 'access audit' rule ignores policy_allow, so granted policy checks are not flagged."""
        decisions = sum(tx["event"] in ("allow", "deny", "policy_allow", "policy_deny") for b in blocks_of("audit") for tx in b.metadata["tx"])
        fired = sum(e["rule"] == "access audit" for e in Pipeline.get()["contracts"].events)
        self.assertEqual(fired, decisions)

    @unittest.expectedFailure
    def test_blocks_hold_10_to_20_transactions(self):
        """KNOWN ISSUE (Table 2: 10-20 transactions per block): the consent audit block holds 80."""
        for b in Pipeline.get()["chain"].blocks[1:]:
            self.assertLessEqual(len(b.metadata["tx"]), 20, f"block {b.index}")

    @unittest.expectedFailure
    def test_tamper_demo_targets_a_patient_record(self):
        """KNOWN ISSUE: the tamper demo edits chain.blocks[1], which is the consent audit block, not a patient record."""
        self.assertEqual(Pipeline.get()["chain"].blocks[1].metadata["kind"], "records")


# ------------------------------------------------------------------ energy (Eq 13) and storage
class TestEnergyAndStorage(unittest.TestCase):
    """Sec 4.6 Eq 13: E_tx = n_enc*e_enc + n_cons*e_cons + n_re*e_re, checked by hand on fixed inputs."""

    @classmethod
    def setUpClass(cls):
        cls.PIPE = pd.DataFrame({"retx_per_group": [0.07], "baseline_retx_per_group": [0.68], "quarantined_pct": [0.0]},
                                index=pd.Index([20], name="fault_rate"))
        cls.rsa_ms, cls.ky_ms, cls.proof_ms = 0.05, 0.01, 0.005
        RESULTS["proof_gen_ms"] = cls.proof_ms
        msgs = {("PBFT", 20): 779.0, ("Raft", 20): 38.0}
        g = lambda p, n, col="lat": msgs[(p, n)]
        old = os.getcwd()
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
            os.chdir(d)                                                               # fig13 is written here, not in your folder
            try:
                cls.out = B.run(cls.PIPE, {"enc": np.full(10, cls.rsa_ms)}, {"enc": np.full(10, cls.ky_ms)}, g)
            finally:
                os.chdir(old)

    def test_eq13_matches_hand_calculation(self):
        e_msg, uj_per_ms = CFG["E_MSG_UJ"], CFG["E_CRYPTO_UJ"] / self.rsa_ms
        base = CFG["E_CRYPTO_UJ"] + 0 + 779 / 20 * e_msg + 0.68 * e_msg
        prop = uj_per_ms * self.ky_ms + uj_per_ms * self.proof_ms + 38 / 20 * e_msg + 0.07 * e_msg
        self.assertAlmostEqual(RESULTS["energy"], 100 * (1 - prop / base), places=6)

    def test_rsa_encryption_costs_30_2_uj(self):                                     # Sec 4.6 constant
        self.assertAlmostEqual(self.out["energy"].iloc[0]["encryption"], CFG["E_CRYPTO_UJ"])

    def test_storage_formula(self):
        bpr = self.out["PIPE_OUT"]["bytes_per_record"]
        self.assertAlmostEqual(RESULTS["storage_mb_day"], bpr * CFG["N_PATIENTS"] * 1440 / 1e6)

    @unittest.expectedFailure
    def test_retransmissions_counted_per_transaction(self):
        """KNOWN ISSUE: one transaction is a one-minute record of 20 reading groups, but the retransmission term uses
        retransmissions per single group. Per transaction it should be 20 x retx_per_group x e_re."""
        self.assertAlmostEqual(self.out["energy"].iloc[1]["retransmissions"], 20 * 0.07 * CFG["E_MSG_UJ"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
