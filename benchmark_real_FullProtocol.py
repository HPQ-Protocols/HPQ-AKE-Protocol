import oqs
import time
import psutil
import os
import numpy as np
import pandas as pd
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

# ==============================================================================
# 0. CÔNG CỤ HỖ TRỢ ĐO TÀI NGUYÊN (CPU/RAM)
# ==============================================================================
def measure_resources(func, *args, n_runs=50):
    """
    Chạy hàm func n_runs lần để đo CPU % và RAM tiêu thụ.
    """
    process = psutil.Process(os.getpid())
    
    # 1. Đo RAM trước khi chạy
    mem_before = process.memory_info().rss / 1024 / 1024  # MB
    
    # 2. Reset CPU counter
    process.cpu_percent(interval=None)
    
    # 3. Chạy workload
    start_time = time.perf_counter()
    for _ in range(n_runs):
        func(*args)
    elapsed = time.perf_counter() - start_time
    
    # 4. Đo CPU (Trung bình trong suốt quá trình chạy)
    cpu_usage = process.cpu_percent(interval=None)
    
    # 5. Đo RAM sau khi chạy
    mem_after = process.memory_info().rss / 1024 / 1024   # MB
    
    # Lấy max RAM để biết đỉnh tiêu thụ
    mem_usage = max(mem_before, mem_after)
    
    return cpu_usage, mem_usage

# ==============================================================================
# 1. HÀM ĐO THỜI GIAN THỰC THI (BENCHMARK PRIMITIVES)
# ==============================================================================

def bench_kyber(n_runs=100):
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    t_kg, t_enc, t_dec = [], [], []
    
    # Warmup
    pk = kem.generate_keypair()
    ct, ss = kem.encap_secret(pk)
    kem.decap_secret(ct)

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
    return np.mean(t_kg), np.mean(t_enc), np.mean(t_dec)

def bench_dilithium(n_runs=100):
    sig = oqs.Signature("ML-DSA-65")
    t_kg, t_sign, t_ver = [], [], []
    message = b"Benchmark data"

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
    return np.mean(t_kg), np.mean(t_sign), np.mean(t_ver)

def bench_rsa(n_runs=50):
    key = RSA.generate(3072)
    cipher = PKCS1_OAEP.new(key)
    msg = b"Dummy 32 bytes key.."
    t_enc, t_dec = [], []

    for _ in range(n_runs):
        t0 = time.perf_counter()
        ct = cipher.encrypt(msg)
        t_enc.append((time.perf_counter() - t0) * 1000)
        
        t0 = time.perf_counter()
        cipher.decrypt(ct)
        t_dec.append((time.perf_counter() - t0) * 1000)
        
    return np.mean(t_enc), np.mean(t_dec)

def bench_classical_tls(n_runs=100):
    """Đo X25519 (Key Exchange) và ECDSA P-256 (Signature) cho TLS 1.3 chuẩn"""
    # 1. X25519 (KeyGen & Agreement)
    t_x25519_kg, t_x25519_agree = [], []
    for _ in range(n_runs):
        t0 = time.perf_counter()
        key = ECC.generate(curve='X25519')
        t_x25519_kg.append((time.perf_counter() - t0) * 1000)
        
        t0 = time.perf_counter()
        _ = key.public_key() # Giả lập thao tác public key
        t_x25519_agree.append((time.perf_counter() - t0) * 1000)

    # 2. ECDSA (P-256) Signature
    t_ecdsa_sign, t_ecdsa_ver = [], []
    key_sign = ECC.generate(curve='P-256')
    signer = DSS.new(key_sign, 'fips-186-3')
    msg = SHA256.new(b"TLS 1.3 Handshake")
    
    for _ in range(n_runs):
        t0 = time.perf_counter()
        sig = signer.sign(msg)
        t_ecdsa_sign.append((time.perf_counter() - t0) * 1000)
        
        t0 = time.perf_counter()
        verifier = DSS.new(key_sign.public_key(), 'fips-186-3')
        verifier.verify(msg, sig)
        t_ecdsa_ver.append((time.perf_counter() - t0) * 1000)

    return np.mean(t_x25519_kg), np.mean(t_x25519_agree), np.mean(t_ecdsa_sign), np.mean(t_ecdsa_ver)

# ==============================================================================
# 2. HÀM GIẢ LẬP ĐỂ ĐO CPU/RAM (WORKLOAD SIMULATION)
# ==============================================================================
def sim_kyber_only():
    k = oqs.KeyEncapsulation("ML-KEM-768")
    pk = k.generate_keypair()
    ct, ss = k.encap_secret(pk)
    k.decap_secret(ct)
    k.free()

def sim_hybrid_tls():
    k = oqs.KeyEncapsulation("ML-KEM-768")
    s = oqs.Signature("ML-DSA-65")
    pk_k = k.generate_keypair()
    pk_s = s.generate_keypair()
    sig = s.sign(b"msg")
    ct, ss = k.encap_secret(pk_k)
    s.verify(b"msg", sig, pk_s)
    k.decap_secret(ct)
    k.free(); s.free()

def sim_kemtls():
    k = oqs.KeyEncapsulation("ML-KEM-768")
    pk1 = k.generate_keypair(); ct1, ss1 = k.encap_secret(pk1); k.decap_secret(ct1)
    pk2 = k.generate_keypair(); ct2, ss2 = k.encap_secret(pk2); k.decap_secret(ct2)
    k.free()

def sim_hpq_ake():
    k = oqs.KeyEncapsulation("ML-KEM-768")
    # Giả lập RSA Encrypt/Decrypt nhẹ hơn tạo key
    key = RSA.generate(2048) 
    cipher = PKCS1_OAEP.new(key)
    pk = k.generate_keypair()
    ct_k, ss = k.encap_secret(pk)
    k.decap_secret(ct_k)
    ct_r = cipher.encrypt(b"32_bytes_key")
    cipher.decrypt(ct_r)
    k.free()

def sim_classical_tls():
    k = ECC.generate(curve='X25519'); _ = k.public_key()
    ks = ECC.generate(curve='P-256')
    signer = DSS.new(ks, 'fips-186-3')
    h = SHA256.new(b"msg")
    sig = signer.sign(h)
    verifier = DSS.new(ks.public_key(), 'fips-186-3')
    verifier.verify(h, sig)

# ==============================================================================
# 3. CHƯƠNG TRÌNH CHÍNH
# ==============================================================================
if __name__ == "__main__":
    print("--- ĐANG ĐO ĐẠC TRÊN PHẦN CỨNG THỰC TẾ (REAL HARDWARE) ---")
    print("Môi trường: Python Calling C Libraries (liboqs & pycryptodome)")
    
    # --- PHẦN 1: ĐO CHI TIẾT TỪNG PHÉP TOÁN (Như code cũ) ---
    print("1. Benchmarking Kyber768...", end="", flush=True)
    k_kg, k_enc, k_dec = bench_kyber()
    print(" Done.")
    
    print("2. Benchmarking Dilithium3...", end="", flush=True)
    d_kg, d_sign, d_ver = bench_dilithium()
    print(" Done.")
    
    print("3. Benchmarking RSA-3072...", end="", flush=True)
    r_enc, r_dec = bench_rsa()
    print(" Done.")

    print("4. Benchmarking TLS 1.3 Classical (X25519+P256)...", end="", flush=True)
    x_kg, x_agree, e_sign, e_ver = bench_classical_tls()
    print(" Done.\n")

    # In lại bảng kết quả Primitive mà bạn muốn giữ
    print(f"{'PRIMITIVE':<20} | {'OP 1 (ms)':<20} | {'OP 2 (ms)':<20}")
    print("-" * 65)
    print(f"{'Kyber768':<20} | Encap: {k_enc:.4f}      | Decap: {k_dec:.4f}")
    print(f"{'Dilithium3':<20} | Verify: {d_ver:.4f}     | Sign:  {d_sign:.4f}")
    print(f"{'RSA-3072':<20} | Encrypt: {r_enc:.4f}    | Decrypt: {r_dec:.4f}")
    print(f"{'X25519':<20} | KeyGen: {x_kg:.4f}     | Agree: {x_agree:.4f}")
    print(f"{'ECDSA-P256':<20} | Verify: {e_ver:.4f}     | Sign:  {e_sign:.4f}")
    print("-" * 65)
    print("\n")

    # --- PHẦN 2: ĐO TÀI NGUYÊN HỆ THỐNG (Phần mới) ---
    print(">> Measuring System Resources (CPU/Memory)... (Please wait)")
    # Tăng n_runs lên để CPU kịp đo (đặc biệt cho Kyber)
    cpu_kyber, mem_kyber = measure_resources(sim_kyber_only, n_runs=500)
    cpu_hybrid, mem_hybrid = measure_resources(sim_hybrid_tls, n_runs=300)
    cpu_kemtls, mem_kemtls = measure_resources(sim_kemtls, n_runs=300)
    cpu_hpq, mem_hpq = measure_resources(sim_hpq_ake, n_runs=20)   # RSA chậm nên chạy ít hơn
    cpu_cls, mem_cls = measure_resources(sim_classical_tls, n_runs=500)

    # --- TÍNH TOÁN TỔNG HỢP ---
    t_kyber_total = k_kg + k_enc + k_dec
    t_hybrid_total = (k_kg + k_enc + k_dec) + (d_sign + d_ver)
    t_kemtls_total = k_kg + (k_enc * 2) + (k_dec * 2)
    t_classical_total = (x_kg * 2) + (x_agree * 2) + e_sign + e_ver
    t_hpq_total = (k_kg + k_enc + k_dec) + (r_enc + r_dec)

    # --- XUẤT BẢNG CUỐI CÙNG ---
    data = {
        "Protocol": [
            "Kyber-only", 
            "TLS 1.3 (Classical)", 
            "Hybrid TLS 1.3", 
            "KEMTLS", 
            "HPQ-AKE (Ours)"
        ],
        "Components": [
            "Kyber768",
            "X25519 + ECDSA",
            "Kyber + Dilithium",
            "Kyber x2",
            "Kyber + RSA"
        ],
        "KeyGen (ms)": [
            k_kg,
            x_kg,
            k_kg, 
            k_kg,
            k_kg
        ],
        "Total CPU Time (ms)": [
            t_kyber_total,
            t_classical_total,
            t_hybrid_total,
            t_kemtls_total,
            t_hpq_total
        ],
        "CPU Utilization (%)": [
            cpu_kyber,
            cpu_cls,
            cpu_hybrid,
            cpu_kemtls,
            cpu_hpq
        ],
        "Memory (MB)": [
            mem_kyber,
            mem_cls,
            mem_hybrid,
            mem_kemtls,
            mem_hpq
        ]
    }
    
    df = pd.DataFrame(data)
    pd.options.display.float_format = '{:.4f}'.format
    
    print("=== BẢNG SO SÁNH HIỆU NĂNG GIAO THỨC ĐẦY ĐỦ ===")
    print(df.to_string(index=False))