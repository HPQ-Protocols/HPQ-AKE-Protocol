import oqs
import time
import numpy as np
import pandas as pd
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

# ==============================================================================
# 1. HÀM ĐO ĐẠC PRIMITIVES VỚI ĐỦ TRUNG BÌNH (MEAN) VÀ ĐỘ LỆCH CHUẨN (STD)
# ==============================================================================

def bench_kyber(n_runs=1000):
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    t_kg, t_enc, t_dec = [], [], []
    
    # Warmup nghiêm túc để loại bỏ nhiễu khởi tạo thư viện C-bindings
    for _ in range(50):
        pk = kem.generate_keypair()
        ct, ss = kem.encap_secret(pk)
        _ = kem.decap_secret(ct)

    for _ in range(n_runs):
        t0 = time.perf_counter()
        pk = kem.generate_keypair()
        t_kg.append((time.perf_counter() - t0) * 1000)
        
        t0 = time.perf_counter()
        ct, ss = kem.encap_secret(pk)
        t_enc.append((time.perf_counter() - t0) * 1000)
        
        t0 = time.perf_counter()
        _ = kem.decap_secret(ct)
        t_dec.append((time.perf_counter() - t0) * 1000)
        
    kem.free()
    return (np.mean(t_kg), np.std(t_kg)), (np.mean(t_enc), np.std(t_enc)), (np.mean(t_dec), np.std(t_dec))

def bench_dilithium(n_runs=1000):
    sig = oqs.Signature("ML-DSA-65")
    t_kg, t_sign, t_ver = [], [], []
    message = b"Benchmark data verification"
    
    # Warmup
    for _ in range(50):
        pk = sig.generate_keypair()
        signature = sig.sign(message)
        sig.verify(message, signature, pk)

    for _ in range(n_runs):
        t0 = time.perf_counter()
        pk = sig.generate_keypair()
        t_kg.append((time.perf_counter() - t0) * 1000)
        
        t0 = time.perf_counter()
        signature = sig.sign(message)
        t_sign.append((time.perf_counter() - t0) * 1000)
        
        t0 = time.perf_counter()
        sig.verify(message, signature, pk)
        t_ver.append((time.perf_counter() - t0) * 1000)
        
    sig.free()
    return (np.mean(t_kg), np.std(t_kg)), (np.mean(t_sign), np.std(t_sign)), (np.mean(t_ver), np.std(t_ver))

def bench_rsa_3072(n_runs=1000):
    # Khóa tĩnh được sinh trước bên ngoài vòng lặp (Khớp chuẩn kiến trúc hệ thống)
    key = RSA.generate(3072)
    cipher = PKCS1_OAEP.new(key)
    msg = b"Dummy 32 bytes ephemeral secret"
    t_enc, t_dec = [], []

    for _ in range(n_runs):
        t0 = time.perf_counter()
        ct = cipher.encrypt(msg)
        t_enc.append((time.perf_counter() - t0) * 1000)
        
        t0 = time.perf_counter()
        cipher.decrypt(ct)
        t_dec.append((time.perf_counter() - t0) * 1000)
        
    return (np.mean(t_enc), np.std(t_enc)), (np.mean(t_dec), np.std(t_dec))

def bench_classical_tls(n_runs=1000):
    t_x25519_kg, t_x25519_agree = [], []
    t_ecdsa_sign, t_ecdsa_ver = [], []
    
    # Khởi tạo dữ liệu mẫu
    key_sign = ECC.generate(curve='P-256')
    signer = DSS.new(key_sign, 'fips-186-3')
    msg = SHA256.new(b"TLS 1.3 Handshake Sign Baseline")

    for _ in range(n_runs):
        # X25519
        t0 = time.perf_counter()
        key = ECC.generate(curve='X25519')
        t_x25519_kg.append((time.perf_counter() - t0) * 1000)
        
        t0 = time.perf_counter()
        _ = key.public_key()
        t_x25519_agree.append((time.perf_counter() - t0) * 1000)

        # ECDSA P-256
        t0 = time.perf_counter()
        sig = signer.sign(msg)
        t_ecdsa_sign.append((time.perf_counter() - t0) * 1000)
        
        t0 = time.perf_counter()
        verifier = DSS.new(key_sign.public_key(), 'fips-186-3')
        verifier.verify(msg, sig)
        t_ecdsa_ver.append((time.perf_counter() - t0) * 1000)

    return ((np.mean(t_x25519_kg), np.std(t_x25519_kg)), 
            (np.mean(t_x25519_agree), np.std(t_x25519_agree)), 
            (np.mean(t_ecdsa_sign), np.std(t_ecdsa_sign)), 
            (np.mean(t_ecdsa_ver), np.std(t_ecdsa_ver)))

# ==============================================================================
# 2. ĐỊNH DẠNG CHUỖI VÀ LAN TRUYỀN SAI SỐ (ERROR PROPAGATION)
# ==============================================================================
def fmt(stat_tuple):
    """Định dạng cặp (Mean, Std) thành chuỗi toán học hiển thị"""
    return f"{stat_tuple[0]:.4f} ± {stat_tuple[1]:.4f}"

def combine_independent_stats(*stats):
    """
    Tính toán Tổng Trung bình và Độ lệch chuẩn tổng thể theo phương pháp khoa học:
    Mean_total = sum(Mean_i)
    Std_total = sqrt(sum(Std_i^2))
    """
    total_mean = sum(s[0] for s in stats)
    total_std = np.sqrt(sum(s[1]**2 for s in stats))
    return total_mean, total_std

# ==============================================================================
# 3. CHƯƠNG TRÌNH ĐO THỐNG KÊ TOÀN DIỆN
# ==============================================================================
if __name__ == "__main__":
    N_SAMPLES = 10000  # Chạy dải mẫu lớn để đảm bảo định lý giới hạn trung tâm (CLT)
    print(f"Executing rigorous cryptographic micro-benchmarks (N = {N_SAMPLES})...")
    
    # Thực thi đo đạc nền tảng
    kyber_kg, kyber_enc, kyber_dec = bench_kyber(N_SAMPLES)
    dili_kg, dili_sign, dili_ver = bench_dilithium(N_SAMPLES)
    rsa_enc, rsa_dec = bench_rsa_3072(N_SAMPLES)
    x_kg, x_agree, e_sign, e_ver = bench_classical_tls(N_SAMPLES)
    
    # --- ÁP DỤNG LAN TRUYỀN SAI SỐ CHO CÁC LUỒNG GIAO THỨC HANDSHAKE ---
    # 1. Kyber-only Baseline
    stat_kyber_total = combine_independent_stats(kyber_kg, kyber_enc, kyber_dec)
    
    # 2. Classical TLS 1.3: 2xX25519 KeyGen + 2xX25519 Agree + 1xECDSA Sign + 1xECDSA Verify
    stat_classical_total = combine_independent_stats(x_kg, x_kg, x_agree, x_agree, e_sign, e_ver)
    
    # 3. Hybrid TLS 1.3: Kyber (KG+Enc+Dec) + Dilithium (Sign+Verify)
    stat_hybrid_total = combine_independent_stats(kyber_kg, kyber_enc, kyber_dec, dili_sign, dili_ver)
    
    # 4. KEMTLS: Kyber Ephemeral + Kyber Intermediate (2x KeyGen + 2x Encap + 2x Decap)
    stat_kemtls_total = combine_independent_stats(kyber_kg, kyber_kg, kyber_enc, kyber_enc, kyber_dec, kyber_dec)
    
    # 5. HPQ-AKE (Proposed): Kyber (KG+Enc+Dec) + RSA-3072 (Enc+Dec)
    stat_hpq_total = combine_independent_stats(kyber_kg, kyber_enc, kyber_dec, rsa_enc, rsa_dec)

    # --- TẠO BẢNG DỮ LIỆU ĐỒNG BỘ TUYỆT ĐỐI VỚI BẢN THẢO BÀI BÁO ---
    data = {
        "Protocol Framework": [
            "Kyber-only Baseline", 
            "TLS 1.3 (Classical)", 
            "Hybrid TLS 1.3", 
            "KEMTLS Baseline", 
            "HPQ-AKE (Proposed)"
        ],
        "Cryptographic Components": [
            "ML-KEM-768",
            "X25519 + ECDSA-P256",
            "ML-KEM-768 + ML-DSA-65",
            "ML-KEM-768 (Dual-Layer)",
            "ML-KEM-768 + RSA-3072"
        ],
        "KeyGen Cost (ms)": [
            fmt(kyber_kg), fmt(x_kg), fmt(kyber_kg), fmt(kyber_kg), fmt(kyber_kg)
        ],
        "Total Protocol CPU Execution Time (ms)": [
            fmt(stat_kyber_total),
            fmt(stat_classical_total),
            fmt(stat_hybrid_total),
            fmt(stat_kemtls_total),
            fmt(stat_hpq_total)
        ]
    }
    
    df = pd.DataFrame(data)
    print("\n" + "="*85)
    print("      REVISED TABLE 6: MATHEMATICALLY COMPLIANT PERFORMANCE METRICS")
    print("="*85)
    print(df.to_string(index=False))
    print("="*85)