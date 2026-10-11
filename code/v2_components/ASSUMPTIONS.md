# Assumptions (the paper gives no value or formula)

**Sensors:** σ = 0.5 read as a standard deviation · true value x*ᵢ ~ U(60, 100), constant per patient · faults independent per reading ·
30% of faults are dropouts, the rest spoofs, half of which are injected by an outside attacker · ε = 1.5 (3σ), also the variance threshold ·
severe deviation > 6 · η = 20-step moving average of the Algorithm 1 flag rate · correction aggregates over readings not classified as faulty ·
retry limit k = 3 · sensor HMAC tags truncated to 8 bytes · "mean smoothing" = mean across sensors · "no correction" = sensor 1 · Kalman design.

**Crypto:** RSA-OAEP padding · mock pk/encapsulation padded to Kyber-768 sizes with SHAKE-256 · mock decapsulation uses only the seed.

**Access control:** 30 s timestamp window · one-time hash-chain tokens (1000 per consent) · nonce/timestamp bound by HMAC keyed with the token ·
pseudonym = truncated SHA-256 of the patient id · ledger keeps H(p), hashed entity id, R, a and t_e beside each policy (needed for Eq 10) ·
"write" implies "read" · RBAC role table.

**Consensus:** 1 ms constant hop delay · 0.01 ms send / 0.04 ms process CPU per message, 20% jitter · 0.05 ms signature check on HotStuff and
Tendermint votes · failover = RequestVote round plus a 150-300 ms election timeout every 10 rounds · congestion = hop delay ×3 ·
blocks committed sequentially · PBFT beyond 20 nodes by a non-negative quadratic fit (plus an optional full-scale simulation as a check).

**System / energy:** gateway HMAC key known to validators · alert rule 50-120 bpm · one ledger record per patient per minute ·
30.2 µJ per crypto op calibrated to one RSA-2048 encryption, other ops scaled by measured CPU time · e_re = one message (16.5 µJ) ·
baseline retransmits every anomalous reading group · Eq 13 evaluated at 20 nodes and 20% faults.

## Places where the paper contradicts itself (the code follows one reading)
* Quorum ⌊N/2⌋+1 (Eq 11) vs ⌈N/2⌉+1 (Lemma 2, Table 2) → Eq 11.
* Fault rates with (Sec 5.3) or without 15% (Table 2, figures) → all five.
* Spoof amplitude "±15 or ±25" (Sec 5.2) vs "±15 to ±25" (Table 2) → fixed values, as Eq 2 says "fixed amplitude".
* "3-of-5 median" vs "3-of-5 majority voting" (contribution 5) → median (Eq 1, Eq 15, Algorithm 1).
* Eq 7 needs the token in clear, but Algorithm 4's text says no secret is transmitted → the token is revealed, so tokens are one-time (hash chain).
* Eq 9 needs the verifier to compute HMAC(k_s, π), but k_s "never leaves the patient device" → ledger stores H(p); the requester presents p.
* "Memory usage" = Python memory (Sec 5.4, abstract) or encrypted-record size (Sec 6.7) → both reported.
* The mock is said to keep IND-CPA security and to use "NIST-recommended primitives" (Sec 3.3); a key derived from public values cannot → noted, not fixed.
* RSA decryption reported faster than encryption (Sec 6.5) and RSA times differ between Fig 7, Fig 8 and the text → measured values reported.
* Consensus: Figs 4, 5, 6 and the text give mutually incompatible latencies; Sec 6.2 says HotStuff/Tendermint are slower than Raft, Sec 6.3 says faster.
* Throughput: 1.26 M TPS (Fig 12, Table 3) is impossible with 10-20 transactions per block and 80-150 ms blocks (Table 2), which allow ≤ 250 TPS;
  "fivefold" (abstract) does not match 1.26 M / 1.08 M.
* Raft is crash-fault tolerant only, while threat A1 is a compromised (Byzantine) node → A1 is handled at the data layer (gateway-signed transactions
  validated by every honest node); Raft itself cannot tolerate an equivocating leader.
* Sensor accuracy: Fig 10 (96-100%) vs Fig 11 / Sec 6.9 (≈85-93%) for the same median filter.
* Energy: Eq 13 uses one constant per crypto op, yet Sec 6.12 attributes savings to faster encryption → op energy scaled by measured CPU time.
