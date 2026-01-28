import oqs
import time
import numpy as np
import matplotlib.pyplot as plt
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP

# ==============================================================================
# 1. CẤU HÌNH DỮ LIỆU & MẠNG
# ==============================================================================
# Kích thước gói tin (Bytes) - Dùng để tính Overhead
SIZES = {
    # Primitives
    "Kyber768_PK": 1184, "Kyber768_CT": 1088,
    "Dilithium3_SIG": 3293, "Dilithium3_PK": 1952,
    "RSA3072_CT": 384, "RSA3072_PK": 384,
    "X25519_PK": 32, "ECDSA_SIG": 64, 
    
    # Overhead (Header + Certificate Chains ước lượng)
    "OH_KyberOnly": 128,               # Chỉ Header
    "OH_TLS13": 1500 + 128,            # Cert RSA truyền thống
    "OH_Hybrid": 8500 + 128,           # Cert Dilithium (Rất nặng)
    "OH_KEMTLS": 7500 + 128,           # Cert Kyber
    "OH_HPQ": 2500 + 128               # Cert RSA (Nhẹ - Ưu điểm của HPQ)
}

# ==============================================================================
# 2. HÀM ĐO ĐẠC THỰC TẾ (BENCHMARK KERNEL)
# ==============================================================================
def measure_func(func, name, n_runs=50):
    """Hàm đo thời gian chạy trung bình của một chức năng"""
    print(f">> Measuring {name}...", end=" ")
    times = []
    try:
        func() # Warmup (chạy nháp 1 lần để nạp cache)
        for _ in range(n_runs):
            t0 = time.perf_counter()
            func()
            times.append((time.perf_counter() - t0) * 1000) # Đổi sang ms
        avg = np.mean(times)
        print(f"{avg:.3f} ms")
        return avg
    except Exception as e:
        print(f"ERROR: {e}")
        return 0

# --- CÁC HÀM WRAPPER CHO TỪNG THUẬT TOÁN ---

def run_kyber():
    # Kyber: KeyGen + Encap + Decap
    # (Mô phỏng 1 vòng trao đổi khóa)
    with oqs.KeyEncapsulation("ML-KEM-768") as k:
        pk = k.generate_keypair()
        ct, ss = k.encap_secret(pk)
        k.decap_secret(ct)

def run_dilithium():
    # Dilithium: Sign + Verify
    # (Fix lỗi API: generate_keypair trả về pk, không lưu nội bộ)
    with oqs.Signature("ML-DSA-65") as s:
        pk = s.generate_keypair()
        msg = b"benchmark_test_message"
        sig = s.sign(msg)
        s.verify(msg, sig, pk)

# Chuẩn bị sẵn Key RSA để không đo thời gian sinh khóa (KeyGen)
# Vì trong Handshake, Server đã có sẵn Key và Cert rồi.
rsa_key = RSA.generate(3072) 
rsa_cipher = PKCS1_OAEP.new(rsa_key)
rsa_msg = b"secret_pre_master_key_32_bytes"

def run_rsa_op():
    # RSA: Encrypt (Client) + Decrypt (Server)
    enc_data = rsa_cipher.encrypt(rsa_msg)
    rsa_cipher.decrypt(enc_data)

def run_ecc_handshake():
    # TLS 1.3 Classical: ECDH (X25519) + ECDSA (P-256)
    # 1. ECDH KeyGen
    k = ECC.generate(curve='X25519')
    k.public_key()
    # 2. ECDSA Sign/Verify
    k_sig = ECC.generate(curve='P-256')
    signer = DSS.new(k_sig, 'fips-186-3')
    hasher = SHA256.new(b"msg")
    sig = signer.sign(hasher)
    verifier = DSS.new(k_sig.public_key(), 'fips-186-3')
    verifier.verify(hasher, sig)

# ==============================================================================
# 3. CHƯƠNG TRÌNH CHÍNH
# ==============================================================================
if __name__ == "__main__":
    print("\n--- [PHẦN 1] BẮT ĐẦU BENCHMARK TRÊN MÁY TÍNH CỦA BẠN ---")
    
    # 1. Đo Primitive Time
    t_kyber = measure_func(run_kyber, "Kyber (KEM)")
    t_dilithium = measure_func(run_dilithium, "Dilithium (Sig)")
    t_rsa = measure_func(run_rsa_op, "RSA (Enc+Dec)")
    t_ecc = measure_func(run_ecc_handshake, "ECC Classical")

    # 2. Tổng hợp dữ liệu cho 5 Giao thức
    protocols = ['Kyber-only', 'TLS 1.3\n(Classical)', 'Hybrid TLS\n(Dilithium)', 'KEMTLS', 'HPQ-AKE\n(Ours)']
    
    # Tính CPU Time tổng (ms) dựa trên kiến trúc giao thức
    cpu_vals = [
        t_kyber,                            # 1. Kyber-only
        t_ecc,                              # 2. TLS 1.3
        t_kyber + t_dilithium,              # 3. Hybrid
        t_kyber * 2,                        # 4. KEMTLS (2 vòng Kyber)
        t_kyber + t_rsa                     # 5. HPQ-AKE
    ]
    
    # Tính Payload Overhead (Bytes)
    size_vals = [
        SIZES["Kyber768_PK"] + SIZES["Kyber768_CT"] + SIZES["OH_KyberOnly"],
        SIZES["X25519_PK"]*2 + SIZES["ECDSA_SIG"] + SIZES["OH_TLS13"],
        SIZES["Kyber768_CT"] + SIZES["Dilithium3_SIG"] + SIZES["OH_Hybrid"],
        SIZES["Kyber768_CT"]*2 + SIZES["OH_KEMTLS"],
        SIZES["Kyber768_CT"] + SIZES["RSA3072_CT"] + SIZES["OH_HPQ"]
    ]

    print("\n--- KẾT QUẢ TỔNG HỢP ---")
    print(f"{'Protocol':<25} | {'CPU (ms)':<10} | {'Size (B)':<10}")
    print("-" * 50)
    for p, c, s in zip(protocols, cpu_vals, size_vals):
        print(f"{p.replace(chr(10), ' '):<25} | {c:<10.2f} | {s:<10}")

    # ==========================================================================
    # 4. VẼ BIỂU ĐỒ (VISUALIZATION)
    # ==========================================================================
    print("\n--- [PHẦN 2] ĐANG VẼ BIỂU ĐỒ ... ---")
    
    # Màu sắc nhận diện
    colors = ['#bdc3c7', '#7f8c8d', '#95a5a6', '#3498db', '#e74c3c'] # Đỏ là HPQ

    # --------------------------------------------------------------------------
    # HÌNH 1: TRADE-OFF (CPU vs SIZE) - Trục đôi
    # --------------------------------------------------------------------------
    fig1, ax1 = plt.subplots(figsize=(12, 6))

    # Cột Size (Trục trái)
    bars = ax1.bar(protocols, size_vals, color=colors, alpha=0.7, width=0.6)
    ax1.set_ylabel('Communication Overhead (Bytes)', fontsize=12, fontweight='bold')
    ax1.set_ylim(0, max(size_vals) * 1.25) # Tăng khoảng trống để ghi số

    for bar in bars:
        h = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., h + 150, f'{int(h)}', 
                 ha='center', fontsize=10, fontweight='bold')

    # Đường CPU (Trục phải)
    ax2 = ax1.twinx()
    ax2.plot(protocols, cpu_vals, color='#2c3e50', marker='D', linewidth=2, markersize=8)
    ax2.set_ylabel('CPU Processing Time (ms)', fontsize=12, fontweight='bold', color='#2c3e50')
    ax2.set_ylim(0, max(cpu_vals) * 1.3)

    for i, v in enumerate(cpu_vals):
        ax2.annotate(f'{v:.3f}ms', (i, v), xytext=(0, 10), textcoords='offset points', 
                     ha='center', color='#2c3e50', fontweight='bold', 
                     bbox=dict(boxstyle="round,pad=0.2", fc="white", alpha=0.9))

    plt.title('Performance Trade-off: Computation vs. Communication', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig('Chart1_TradeOff.png', dpi=300)
    print(">> Đã lưu: Chart1_TradeOff.png")

    # --------------------------------------------------------------------------
    # HÌNH 2: NETWORK LATENCY (SUBPLOTS - TÁCH 3 MÔI TRƯỜNG)
    # --------------------------------------------------------------------------
    # 3 Kịch bản mạng
    scenarios = [
        {'name': 'Fiber / LAN\n(100Mbps, 10ms)', 'bw': 100, 'rtt': 10},
        {'name': '4G / Wi-Fi\n(10Mbps, 50ms)',   'bw': 10,  'rtt': 50},
        {'name': 'Satellite / IoT\n(50kbps, 600ms)', 'bw': 0.05, 'rtt': 600}
    ]

    fig2, axes = plt.subplots(1, 3, figsize=(18, 6))
    fig2.suptitle('End-to-End Handshake Latency across Network Environments', fontsize=16, fontweight='bold', y=1.05)

    for i, ax in enumerate(axes):
        scenario = scenarios[i]
        bw_bytes_ms = (scenario['bw'] * 1e6) / 8 / 1000 # Đổi Bandwidth ra Bytes/ms
        
        # Tính Latency cho môi trường này
        latencies = []
        for cpu, size in zip(cpu_vals, size_vals):
            trans_delay = size / bw_bytes_ms
            total = cpu + scenario['rtt'] + trans_delay
            latencies.append(total)

        # Vẽ cột
        bars = ax.bar(protocols, latencies, color=colors, alpha=0.9, width=0.6)
        
        # Trang trí
        ax.set_title(scenario['name'], fontsize=12, fontweight='bold', pad=10)
        ax.set_xticklabels(protocols, rotation=45, ha='right', fontsize=9)
        ax.set_ylabel('Latency (ms)', fontweight='bold')
        ax.grid(axis='y', linestyle='--', alpha=0.3)
        
        # Limit Y axis để chừa chỗ cho số
        ax.set_ylim(0, max(latencies) * 1.25)

        # Hiển thị số liệu
        for bar in bars:
            h = bar.get_height()
            txt = f'{h:.1f}' if h < 100 else f'{int(h)}' # Số nhỏ thì lấy lẻ, số to lấy chẵn
            ax.text(bar.get_x() + bar.get_width()/2., h, txt, 
                    ha='center', va='bottom', fontsize=9, fontweight='bold')

        # --- ĐẶC BIỆT: Mũi tên so sánh ở hình Satellite (Cuối cùng) ---
        if i == 2:
            lat_hybrid = latencies[2] # Hybrid TLS
            lat_hpq = latencies[4]    # HPQ-AKE
            imp = (1 - lat_hpq/lat_hybrid) * 100
            
            # Vẽ mũi tên
            ax.annotate(f'HPQ Faster\n{imp:.0f}%', 
                        xy=(4, lat_hpq),             # Điểm đầu (HPQ)
                        xytext=(4, lat_hybrid),      # Điểm text (Ngang với Hybrid)
                        arrowprops=dict(facecolor='red', arrowstyle="->", connectionstyle="arc3,rad=-0.3"),
                        ha='center', fontsize=11, fontweight='bold', color='red',
                        bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="red"))

    plt.tight_layout()
    plt.savefig('Chart2_NetworkLatency.png', dpi=300, bbox_inches='tight')
    print(">> Đã lưu: Chart2_NetworkLatency.png")
    
    plt.show() # Hiển thị lên màn hình