import argparse
import csv
import json
import platform
from pathlib import Path

import numpy as np


BASE_RTTS_MS = (1, 20, 50, 100, 200, 400, 600, 1000)
JITTER_FRACTIONS = (0.0, 0.12, 0.30)
SEEDS = tuple(range(42, 52))
SAMPLES_PER_SEED = 10_000
CPU_HPQAKE_MS = 7.1053
CPU_TLS_MS = 2.3340
RTT_MULTIPLIER_GAP = 0.5
WIRE_BYTES = {"hpq_ake": 5828, "pre_cached": 6409, "full": 13369}


def crossover_mbps(rtt_ms, baseline):
    wire_gap_bits = 8 * (WIRE_BYTES[baseline] - WIRE_BYTES["hpq_ake"])
    penalty_seconds = (
        CPU_HPQAKE_MS - CPU_TLS_MS + RTT_MULTIPLIER_GAP * np.asarray(rtt_ms)
    ) / 1000.0
    return wire_gap_bits / penalty_seconds / 1_000_000.0


def write_csv(path, rows):
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def run(output_dir):
    if output_dir.is_absolute():
        raise ValueError("Use an output directory relative to the workspace")
    output_dir.mkdir(parents=True, exist_ok=True)
    noise_by_seed = {
        seed: np.random.Generator(np.random.PCG64(seed)).exponential(
            scale=1.0, size=SAMPLES_PER_SEED
        )
        for seed in SEEDS
    }
    summary = []
    seed_results = []
    for base_rtt_ms in BASE_RTTS_MS:
        for jitter_fraction in JITTER_FRACTIONS:
            for baseline in ("pre_cached", "full"):
                samples = []
                medians = []
                for seed in SEEDS:
                    realized_rtt_ms = base_rtt_ms * (
                        1.0 + jitter_fraction * noise_by_seed[seed]
                    )
                    thresholds = crossover_mbps(realized_rtt_ms, baseline)
                    samples.append(thresholds)
                    median = float(np.quantile(thresholds, 0.5, method="linear"))
                    medians.append(median)
                    seed_results.append({
                        "base_rtt_ms": base_rtt_ms,
                        "jitter_fraction": jitter_fraction,
                        "baseline": baseline,
                        "seed": seed,
                        "median_crossover_mbps": median,
                    })
                quantiles = np.quantile(
                    np.concatenate(samples), (0.05, 0.5, 0.95), method="linear"
                )
                summary.append({
                    "base_rtt_ms": base_rtt_ms,
                    "jitter_fraction": jitter_fraction,
                    "baseline": baseline,
                    "q05_crossover_mbps": float(quantiles[0]),
                    "median_crossover_mbps": float(quantiles[1]),
                    "q95_crossover_mbps": float(quantiles[2]),
                    "min_seed_median_mbps": min(medians),
                    "max_seed_median_mbps": max(medians),
                })
    write_csv(output_dir / "summary.csv", summary)
    write_csv(output_dir / "seed_medians.csv", seed_results)
    lookup = {
        (row["base_rtt_ms"], row["jitter_fraction"], row["baseline"]): row
        for row in summary
    }
    table_rows = []
    for base_rtt_ms in BASE_RTTS_MS:
        cells = [str(base_rtt_ms)]
        for jitter_fraction in JITTER_FRACTIONS:
            for baseline in ("pre_cached", "full"):
                median = lookup[(base_rtt_ms, jitter_fraction, baseline)][
                    "median_crossover_mbps"
                ]
                cells.append(f"{median:.4f}")
        table_rows.append(" & ".join(r"\rev{" + cell + "}" for cell in cells) + r" \\")
    (output_dir / "table_rows.tex").write_text("\n".join(table_rows) + "\n")
    metadata = {
        "experiment": "New RTT sensitivity analysis, not a replay of original latency results",
        "python_version": platform.python_version(),
        "numpy_version": np.__version__,
        "rng": "numpy.random.Generator(numpy.random.PCG64(seed))",
        "seeds": SEEDS,
        "samples_per_seed": SAMPLES_PER_SEED,
        "base_rtts_ms": BASE_RTTS_MS,
        "jitter_fractions": JITTER_FRACTIONS,
        "jitter_model": "RTT_i = base_RTT * (1 + jitter_fraction * E_i), E_i ~ Exp(scale=1)",
        "coupling": "Same E_i reused across baselines, base RTTs and jitter fractions within each seed",
        "cpu_ms": {"hpq_ake": CPU_HPQAKE_MS, "both_tls_baselines": CPU_TLS_MS},
        "cpu_sampling": "None; manuscript means held fixed to isolate RTT effects",
        "rtt_multiplier_gap": RTT_MULTIPLIER_GAP,
        "wire_bytes": WIRE_BYTES,
        "extra_discretionary_padding_bytes": 0,
        "quantiles": "Pooled 100000 samples per setting; numpy.quantile(method='linear'); no trimming",
        "percentile_interpretation": "Modeled variability, not confidence intervals",
        "cryptographic_operations_executed": False,
        "historical_seed_verified": True,
        "historical_oaep_configuration_verified": True,
        "historical_padding_verification_scope": "RSA-OAEP benchmark defaults verified; AEAD and TLS record serialization are not implemented by the supplied evaluation scripts",
        "original_replay_manifest": "analysis/original_results/manifest.json",
    }
    (output_dir / "manifest.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"Saved {len(summary)} settings and {len(seed_results)} seed medians to {output_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=Path("analysis/rtt_results"))
    run(parser.parse_args().output_dir)