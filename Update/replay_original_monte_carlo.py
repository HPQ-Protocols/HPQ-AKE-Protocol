import argparse
import ast
import contextlib
import copy
import csv
import hashlib
import io
import json
import platform
from pathlib import Path
from zipfile import ZipFile

import numpy as np


ARCHIVE_PATH = Path("prism-uploads/HPQ-AKE-Protocol-main.zip")
ARCHIVE_ROOT = "HPQ-AKE-Protocol-main/"


SOURCE_PATHS = tuple(Path("prism-uploads") / name for name in (
    "HoanHaoTongHop.py",
    "Microbenchmark_ProtocolModelingFinal.py",
    "Monte-Carlo_BoxplotFinal.py",
    "Break-Even_PlotFinal.py",
))
GLOBAL_NAMES = (
    "PROTOCOLS", "CPU_VALS", "CPU_STD", "PROTOCOL_SIZES_BYTES",
    "RTT_FACTORS", "MTU_PAYLOAD", "TCP_IP_HEADER",
)


def replay():
    source_path = f"{ARCHIVE_PATH}!{ARCHIVE_ROOT}{SOURCE_PATHS[0].name}"
    with ZipFile(ARCHIVE_PATH) as bundle:
        source = bundle.read(ARCHIVE_ROOT + SOURCE_PATHS[0].name)
    tree = ast.parse(source.decode("utf-8-sig"))
    namespace = {"np": np}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in GLOBAL_NAMES:
                namespace[target.id] = ast.literal_eval(node.value)
    if not all(name in namespace for name in GLOBAL_NAMES):
        raise ValueError("Reference source no longer has the expected configuration")
    function = copy.deepcopy(next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "run_monte_carlo_simulation"
    ))
    loop_index = next(
        index for index, node in enumerate(function.body)
        if isinstance(node, ast.For)
    )
    function.body = function.body[:loop_index + 1]
    seed_calls = [
        node for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute) and node.func.attr == "seed"
    ]
    if len(seed_calls) != 1 or ast.literal_eval(seed_calls[0].args[0]) != 42:
        raise ValueError("Reference seed has changed; review the reproducibility record")
    function.body.append(ast.Return(value=ast.Tuple(elts=[
        ast.Name(id=name, ctx=ast.Load())
        for name in ("simulation_data", "NETWORK_CONFIG", "NUM_SIMULATIONS")
    ], ctx=ast.Load())))
    module = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    exec(compile(module, str(source_path), "exec"), namespace)
    previous_rng_state = np.random.get_state()
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            samples, network, sample_count = namespace[function.name]()
        rng_name = np.random.get_state()[0]
    finally:
        np.random.set_state(previous_rng_state)
    return namespace, samples, network, sample_count, rng_name


def run(output_dir):
    if output_dir.is_absolute():
        raise ValueError("Use an output directory relative to the workspace")
    namespace, samples, network, sample_count, rng_name = replay()
    if sample_count != 10000 or rng_name != "MT19937":
        raise ValueError("Reference sampling configuration has changed")
    rows = []
    for index, sample in enumerate(samples):
        payload = namespace["PROTOCOL_SIZES_BYTES"][index]
        wire_bytes = int(payload + np.ceil(payload / namespace["MTU_PAYLOAD"]) * namespace["TCP_IP_HEADER"])
        rows.append({
            "protocol": namespace["PROTOCOLS"][index].replace("\n", " "),
            "samples": len(sample),
            "payload_bytes": payload,
            "wire_bytes": wire_bytes,
            "cpu_mean_input_ms": namespace["CPU_VALS"][index],
            "cpu_std_input_ms": namespace["CPU_STD"][index],
            "rtt_multiplier": namespace["RTT_FACTORS"][index],
            "median_ms": float(np.median(sample)),
            "figure_label_ms": int(np.median(sample)),
            "mean_ms": float(np.mean(sample)),
            "std_ms_ddof0": float(np.std(sample)),
        })
    if [rows[index]["figure_label_ms"] for index in (2, 3, 5)] != [2791, 1678, 1914]:
        raise ValueError("Replay no longer matches the manuscript's figure labels")
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "summary.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    with ZipFile(ARCHIVE_PATH) as bundle:
        archive_fingerprints = {
            item.filename: hashlib.sha256(bundle.read(item.filename)).hexdigest()
            for item in bundle.infolist() if not item.is_dir()
        }
    metadata = {
        "experiment": "Replay of original Monte Carlo arithmetic from the official archived HoanHaoTongHop.py",
        "archive_path": str(ARCHIVE_PATH),
        "archive_sha256": hashlib.sha256(ARCHIVE_PATH.read_bytes()).hexdigest(),
        "selected_source_member": ARCHIVE_ROOT + SOURCE_PATHS[0].name,
        "archive_member_sha256": archive_fingerprints,
        "extraction": "Original function prefix through its sampling loop, with original constant inputs; plotting and cryptographic benchmarking omitted",
        "source_sha256": {
            ARCHIVE_ROOT + path.name: archive_fingerprints[ARCHIVE_ROOT + path.name]
            for path in SOURCE_PATHS
        },
        "python_version": platform.python_version(),
        "numpy_version": np.__version__,
        "rng": "numpy.random singleton RandomState (MT19937)",
        "seed": 42,
        "samples_per_protocol": sample_count,
        "network_configuration": network,
        "draw_order": "One initialization, original six-protocol order; all normal CPU draws then all exponential jitter draws for each protocol",
        "cpu_distribution": "Normal(declared mean, declared std), clipped below at 0.001 ms",
        "jitter_distribution": "Exponential(scale=0.12 * base_RTT_ms * protocol_RTT_multiplier); added only to propagation",
        "figure_label_convention": "int(median), truncation rather than rounding to nearest ms",
        "full_relative_latency_reduction_percent": 100 * (1 - rows[5]["median_ms"] / rows[2]["median_ms"]),
        "historical_seed_verified": True,
        "historical_oaep_configuration_verified": True,
        "oaep_configuration": {
            "verification_basis": "Unparameterized PKCS1_OAEP.new calls in both supplied benchmark sources, interpreted using PyCryptodome v3.20.0 defaults",
            "reference_source": "https://raw.githubusercontent.com/Legrandin/pycryptodome/v3.20.0/lib/Crypto/Cipher/PKCS1_OAEP.py",
            "rsa_modulus_bits": 3072,
            "oaep_hash": "SHA-1",
            "mgf": "MGF1-SHA-1",
            "label_hex": "",
            "random_source": "Crypto.Random.get_random_bytes; not the NumPy simulation seed",
            "ciphertext_bytes": 384,
            "standalone_benchmark_message_bytes": 28,
            "integrated_demo_message_bytes": 32,
        },
        "aead_and_tls_record_execution": "Not implemented in the supplied evaluation scripts; aggregate payload sizes are model inputs",
        "extra_discretionary_padding_bytes_in_model": 0,
        "hardware_microbenchmarks_rerun": False,
        "raw_timing_provenance_verified_by_this_replay": False,
    }
    (output_dir / "manifest.json").write_text(json.dumps(metadata, indent=2) + "\n")
    for row in rows:
        print(f"{row['protocol']}: median={row['median_ms']:.9f} ms, label={row['figure_label_ms']}")
    print(f"Saved source fingerprints and replay results to {output_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=Path("analysis/original_results"))
    run(parser.parse_args().output_dir)