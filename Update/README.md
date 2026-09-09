# HPQ-AKE reproducibility package

Two separate experiments are provided. The authoritative source snapshot is
`prism-uploads/HPQ-AKE-Protocol-main.zip`. The archive and its contents remain
unchanged. The ZIP checksum, all member checksums, and the selected reference
script are recorded in `original_results/manifest.json`. The four previously
uploaded scripts are byte-identical to their counterparts in this archive.

## 1. Replay the original latency simulation

From the project root, using the existing Python and NumPy installation:

```sh
python analysis/replay_original_monte_carlo.py
```

The runner reads `HPQ-AKE-Protocol-main/HoanHaoTongHop.py` directly from the
ZIP and executes its original sampling loop and constant inputs. No extraction
or separate loose copy of that script is required. It omits unrelated cryptographic
benchmark imports and plotting, allowing the original Monte Carlo arithmetic
to run with NumPy alone. It does not substitute a newly written sampling model.

The original seed is **42**, using NumPy's singleton RandomState with MT19937,
10,000 samples per protocol. Seed initialization occurs once before the six
protocols, in source order. Each protocol draws all CPU samples first from the
normal distribution using its declared mean and standard deviation, clips
values below 0.001 ms, then draws exponential jitter. Jitter scale is
`0.12 * base_RTT_ms * protocol_RTT_multiplier`, added only to propagation.
CPU inputs are declared profiles, not raw-sample bootstraps. The integrated
50-iteration demonstration benchmark does not update the simulation constants.

The replay retains the full medians:

| Protocol | Median (ms) | Figure label `int(median)` |
| --- | ---: | ---: |
| Hybrid TLS Full | 2791.062850 | 2791 |
| Hybrid TLS Pre-cached | 1678.138330 | 1678 |
| HPQ-AKE | 1914.732601 | 1914 |

Labels truncate the fractional part; they do not round to the nearest integer.
The full-precision reduction against Full is approximately 31.3977%.
No samples are trimmed for numerical summaries; the original plot hides outlier
markers. `original_results/summary.csv` retains all six protocols, and the
manifest records runtime versions, inputs, draw order, and source fingerprints.
The replay does not remeasure or independently verify the historical hardware
CPU profiles.

### RSA-OAEP configuration

Both supplied benchmark sources call `PKCS1_OAEP.new(key)` without optional
arguments. Interpreted under the manuscript's PyCryptodome v3.20.0, this selects
SHA-1, MGF1-SHA-1, an empty label, and `Crypto.Random.get_random_bytes` for OAEP
randomness. NumPy's simulation seed does not control cryptographic randomness.
RSA-3072 ciphertext occupies 384 bytes including OAEP encoding.

`Microbenchmark_ProtocolModelingFinal.py` uses the 28-byte literal
`b"Dummy 32-byte session secret"`; its text is not its actual byte length.
The integrated driver uses `b"A" * 32`. The standalone microbenchmark uses 100
warm-up iterations and 10,000 timed iterations per routine. Its earlier
protocol-aggregation formula contains one RSA encryption/decryption pair and
should not be mistaken for the integrated driver's current declared CPU profile.
The latter profile is the input used to reproduce the manuscript's simulation.

AES-GCM and TLS record serialization are not executed by these evaluation
scripts. Their nonce/tag lengths and record-padding policy therefore are not
measured runtime configurations of this aggregate network model. No separate
discretionary padding increment is added to the declared payload-size inputs.

### Source version selection

- `HoanHaoTongHop.py`: reference for current latency and dual-baseline network
  modeling (5668-byte HPQ-AKE payload; 7.1053 ms CPU mean).
- `Microbenchmark_ProtocolModelingFinal.py`: source of the standalone primitive
  benchmark routines and OAEP configuration, with the aggregation distinction
  noted above.
- `Monte-Carlo_BoxplotFinal.py`: earlier configuration, 5000 samples, 4100-byte
  HPQ-AKE payload, 3.5577 ms CPU mean, and jitter applied to transmission plus
  propagation. It is not the reference for the current figure.
- `Break-Even_PlotFinal.py`: earlier 4100-byte/3.5577 ms configuration, not the
  current dual-baseline crossover figure.

The archive also contains `TongHop1626RedTeamFinal.py`, which differs from
`HoanHaoTongHop.py` by using a 5284-byte rather than 5668-byte HPQ-AKE payload.
The dated `2152026...` scripts and archived plot images are retained snapshots,
not interchangeable parameter sources for the current manuscript. The reference
selection is based on reproducing the current manuscript's numerical results;
no claim is made that every archived image is byte-identical to the manuscript's
figure files.

## 2. Supplementary RTT-sensitivity experiment

```sh
python analysis/rtt_sensitivity.py
```

This newly executed experiment varies the RTT of the manuscript's crossover
model; it is not a replacement for the original latency simulation. Results in
`rtt_results/` include `summary.csv`, `seed_medians.csv`, `table_rows.tex`, and
`manifest.json`. The latter records runtime versions and the precise inputs.
Use the recorded versions for sample-for-sample reproduction.

PCG64 is initialized independently with seeds 42 through 51, 10,000 samples per
seed. Each seed draws one array of unit-scale exponential variates reused across
base RTTs, jitter fractions, and both baselines. This common-random-number
coupling isolates the model comparison. Unlike the original latency simulation,
CPU means are fixed and not sampled, and protocol comparisons are paired.

Base RTTs are 1, 20, 50, 100, 200, 400, 600, and 1000 ms. Realized RTT is
`base_RTT * (1 + jitter_fraction * Exp(scale=1))`, for fractions 0, 0.12, and
0.30. The exponential addition has mean and standard deviation equal to
`jitter_fraction * base_RTT`; it is positive, not zero-mean noise.

Crossover bandwidth in Mbps is
`8 * wire_byte_gap / ((7.1053 - 2.3340 + 0.5 * RTT_ms) / 1000) / 1e6`.
Wire sizes are 5828 bytes (HPQ-AKE), 6409 (Pre-cached), and 13369 (Full).
No extra discretionary padding bytes are added and no crypto operation is run.

Each stochastic summary pools 100,000 samples for the setting. Percentiles use
NumPy's linear quantile method without trimming and describe modeled variability,
not confidence intervals. Per-seed medians are also retained. Zero-jitter entries
are deterministic and seed independent. The SHA-1 setting describes the original
RSA benchmark, not a change to the supplementary statistical experiment.
## 3. Authorized key-schedule correction (September 8, 2026)

The revised manuscript now includes the existing RSA secret encapsulated by B
to A in the master KDF and uses the separate expand context `HPQ-AKE/master`.
This corrects the responder-acceptance issue documented in
`reviewer2_comment2_kci_review.md`; that document and the frozen
`kci_counterexample.py` describe the pre-correction schedule.

```sh
python analysis/kci_revision_checks.py
```

The new functional checks preserve the old counterexample as a regression,
verify its rejection with the corrected schedule, and exercise honest key
agreement and the role-specific missing-secret conditions. These are
ideal-primitive checks, not a reduction proof or hardware benchmark. Results
are recorded separately in `kci_revision_checks.json`. The original source ZIP,
CPU profiles, latency replay, and RTT-sensitivity outputs remain historical
artifacts; none is relabeled as a timing measurement of the corrected KDF.
See `reviewer2_comment2_response.md` for the author response and precise scope.