import time
import numpy as np
import pandas as pd
import oqs
from cryptography.hazmat.primitives.asymmetric import x25519
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP

# ==============================================================================
# 1. CORE UTILITIES & STATISTICS (Tối ưu hóa hiệu năng)
# ==============================================================================
def now_ms():
    return time.perf_counter_ns() / 1e6

def compute_stats(samples):
    arr = np.array(samples)
    std = np.std(arr, ddof=1)
    return {
        "mean": np.mean(arr), "std": std,
        "median": np.median(arr), "p95": np.percentile(arr, 95),
        "ci95": 1.96 * (std / np.sqrt(len(arr)))
    }

def combine_independent_stats(*stats_objects):
    return {
        "mean": sum(s["mean"] for s in stats_objects),
        "std": np.sqrt(sum(s["std"] ** 2 for s in stats_objects)),
        "median": None, "p95": None,
        "ci95": np.sqrt(sum(s["ci95"] ** 2 for s in stats_objects))
    }

def fmt(stats):
    m, s, ci = stats.get("mean", 0), stats.get("std", 0), stats.get("ci95", 0)
    med, p95 = stats.get("median"), stats.get("p95")
    if med is not None and p95 is not None:
        return f"{m:.4f} ± {s:.4f} (median={med:.4f}, p95={p95:.4f}, 95%CI=±{ci:.4f})"
    return f"{m:.4f} ± {s:.4f} (95%CI=±{ci:.4f})"

# ==============================================================================
# 2. BENCHMARK RUNNERS
# ==============================================================================
def bench_kyber(n_runs=1000):
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        for _ in range(100):
            pk = kem.generate_keypair()
            kem.decap_secret(kem.encap_secret(pk)[0])
        t_kg, t_enc, t_dec = np.zeros(n_runs), np.zeros(n_runs), np.zeros(n_runs)
        for i in range(n_runs):
            t0 = now_ms(); pk = kem.generate_keypair(); t_kg[i] = now_ms() - t0
            t0 = now_ms(); ct, _ = kem.encap_secret(pk); t_enc[i] = now_ms() - t0
            t0 = now_ms(); kem.decap_secret(ct); t_dec[i] = now_ms() - t0
    return compute_stats(t_kg), compute_stats(t_enc), compute_stats(t_dec)

def bench_dilithium(n_runs=1000):
    with oqs.Signature("ML-DSA-65") as sig:
        msg = b"Benchmark verification payload"
        for _ in range(100):
            pk = sig.generate_keypair()
            sig.verify(msg, sig.sign(msg), pk)
        t_kg, t_sign, t_ver = np.zeros(n_runs), np.zeros(n_runs), np.zeros(n_runs)
        for i in range(n_runs):
            t0 = now_ms(); pk = sig.generate_keypair(); t_kg[i] = now_ms() - t0
            t0 = now_ms(); signature = sig.sign(msg); t_sign[i] = now_ms() - t0
            t0 = now_ms(); sig.verify(msg, signature, pk); t_ver[i] = now_ms() - t0
    return compute_stats(t_kg), compute_stats(t_sign), compute_stats(t_ver)

def bench_rsa_3072(n_runs=1000):
    key = RSA.generate(3072)
    cipher = PKCS1_OAEP.new(key)
    msg = b"Dummy 32-byte session secret"
    for _ in range(100):
        cipher.decrypt(cipher.encrypt(msg))
    t_enc, t_dec = np.zeros(n_runs), np.zeros(n_runs)
    for i in range(n_runs):
        t0 = now_ms(); ct = cipher.encrypt(msg); t_enc[i] = now_ms() - t0
        t0 = now_ms(); cipher.decrypt(ct); t_dec[i] = now_ms() - t0
    return compute_stats(t_enc), compute_stats(t_dec)

def bench_classical_tls(n_runs=1000):
    key_sign = ECC.generate(curve='P-256')
    signer, msg = DSS.new(key_sign, 'fips-186-3'), SHA256.new(b"TLS 1.3 Classical")
    for _ in range(100):
        alice_priv, bob_priv = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
        bob_priv.exchange(alice_priv.public_key())
        DSS.new(key_sign.public_key(), 'fips-186-3').verify(msg, signer.sign(msg))

    t_x25519_kg, t_x25519_agree = np.zeros(n_runs), np.zeros(n_runs)
    t_ecdsa_sign, t_ecdsa_ver = np.zeros(n_runs), np.zeros(n_runs)
    for i in range(n_runs):
        t0 = now_ms()
        alice_priv, bob_priv = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
        t_x25519_kg[i] = now_ms() - t0
        
        alice_pub, bob_pub = alice_priv.public_key(), bob_priv.public_key()
        t0 = now_ms(); alice_priv.exchange(bob_pub); bob_priv.exchange(alice_pub); t_x25519_agree[i] = now_ms() - t0
        
        t0 = now_ms(); sig = signer.sign(msg); t_ecdsa_sign[i] = now_ms() - t0
        verifier = DSS.new(key_sign.public_key(), 'fips-186-3')
        t0 = now_ms(); verifier.verify(msg, sig); t_ecdsa_ver[i] = now_ms() - t0
    return compute_stats(t_x25519_kg), compute_stats(t_x25519_agree), compute_stats(t_ecdsa_sign), compute_stats(t_ecdsa_ver)

# ==============================================================================
# 3. MAIN EXECUTION
# ==============================================================================
if __name__ == "__main__":
    N_SAMPLES = 10000
    print("=" * 120 + f"\nExecuting rigorous cryptographic microbenchmarks (N={N_SAMPLES})\n" + "=" * 120)

    kyber_kg, kyber_enc, kyber_dec = bench_kyber(N_SAMPLES)
    dili_kg, dili_sign, dili_ver = bench_dilithium(N_SAMPLES)
    rsa_enc, rsa_dec = bench_rsa_3072(N_SAMPLES)
    x_kg, x_agree, e_sign, e_ver = bench_classical_tls(N_SAMPLES)

    # LẮP GHÉP CÔNG BẰNG VẬT LÝ & LOGIC
    stat_kyber_total = combine_independent_stats(kyber_kg, kyber_enc, kyber_dec)
    
    # Đã sửa lỗi tính trùng lặp. Chỉ truyền 1 lần.
    stat_classical_total = combine_independent_stats(x_kg, x_agree, e_sign, e_ver)
    
    # Hybrid = Classical + Post-Quantum 
    stat_hybrid_total = combine_independent_stats(
        x_kg, x_agree, e_sign, e_ver, 
        kyber_kg, kyber_enc, kyber_dec, dili_sign, dili_ver
    )
    
    stat_kemtls_total = combine_independent_stats(kyber_kg, kyber_kg, kyber_enc, kyber_enc, kyber_dec, kyber_dec)
    
    # HPQ-AKE Mutual Auth
    stat_hpq_total = combine_independent_stats(kyber_kg, kyber_enc, kyber_dec, rsa_enc, rsa_dec)

    # [RED TEAM DIRECTIVE - ĐỐI CHỨNG CÔNG BẰNG]: 
    # Bổ sung Hybrid TLS 1.3 (Pre-cached) vào Baseline. 
    # Về mặt CPU, nó thực thi 100% giống bản Full (vẫn phải Sign/Verify), chỉ khác kích thước truyền tải mạng.
    df_protocol = pd.DataFrame({
        "Protocol Framework": [
            "Kyber-only Baseline", 
            "TLS 1.3 (Classical)", 
            "Hybrid TLS 1.3 (Full)", 
            "Hybrid TLS 1.3 (Pre-cached)", # <-- BỔ SUNG MINH BẠCH
            "KEMTLS Baseline", 
            "HPQ-AKE (Proposed)"
        ],
        "Cryptographic Components": [
            "ML-KEM-768", 
            "X25519 + ECDSA-P256", 
            "Classical + PQ Dual", 
            "Classical + PQ Dual",         # <-- Cấu trúc Crypto y hệt
            "ML-KEM-768 Dual", 
            "ML-KEM-768 + RSA-3072"
        ],
        "Protocol CPU Time (ms)": [
            fmt(stat_kyber_total), 
            fmt(stat_classical_total), 
            fmt(stat_hybrid_total), 
            fmt(stat_hybrid_total),        # <-- Dùng chung thông số CPU với Full
            fmt(stat_kemtls_total), 
            fmt(stat_hpq_total)
        ]
    })
    
    print("\n" + "=" * 120 + "\nREVISED TABLE 6: EMPIRICAL + ANALYTICAL MICROBENCHMARK MODEL (PHYSICS COMPLIANT)\n" + "=" * 120)
    print(df_protocol.to_string(index=False))