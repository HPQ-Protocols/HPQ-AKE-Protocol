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
SIZES = {
    # Primitives
    "Kyber768_PK": 1184, "Kyber768_CT": 1088,
    "Dilithium3_SIG": 3293, "Dilithium3_PK": 1952,
    "RSA3072_CT": 384, "RSA3072_PK": 384,
    "X25519_PK": 32, "ECDSA_SIG": 64, 
    
    # Overhead (Header + Cert Chain)
    "OH_KyberOnly": 128,               # Chỉ Header (Baseline)
    "OH_TLS13": 1500 + 128,            # Cert RSA thường
    "OH_Hybrid": 4500 + 128,           # Cert Dilithium (Nặng)
    "OH_KEMTLS": 3500 + 128,           # Cert Kyber
    "OH_HPQ": 1500 + 128               # Cert RSA (Nhẹ - Ưu điểm)
}

# Cấu hình mạng Vệ tinh (Scenario khắc nghiệt nhất)
NETWORK_CONFIG = {
    "Bandwidth_kbps": 50,    # 50 kbps
    "RTT_ms": 600,           # 600ms latency
    "Jitter_Percent": 0.05   # Nhiễu 5%
}

# ==============================================================================
# 2. ĐO ĐẠC CPU THỰC TẾ (REAL BENCHMARK)
# ==============================================================================
print("--- [BƯỚC 1] ĐO THỜI GIAN XỬ LÝ CPU THỰC TẾ ---")

# Setup Keys (Để không đo thời gian sinh khóa RSA/ECC vì Server có sẵn)
rsa_key = RSA.generate(3072)
rsa_cipher = PKCS1_OAEP.new(rsa_key)
rsa_msg = b"secret_key_32_bytes"

ecc_key = ECC.generate(curve='P-256')
signer = DSS.new(ecc_key, 'fips-186-3')
hasher = SHA256.new(b"msg")
sig_ecc = signer.sign(hasher)
verifier = DSS.new(ecc_key.public_key(), 'fips-186-3')

def measure_avg(func, name, n_runs=50):
    print(f">> Measuring {name}...", end=" ")
    times = []
    try:
        func() # Warmup
        for _ in range(n_runs):
            t0 = time.perf_counter()
            func()
            times.append((time.perf_counter() - t0) * 1000)
        avg = np.mean(times)
        print(f"{avg:.3f} ms")
        return avg
    except Exception as e:
        print(f"ERR: {e}")
        return 0

# --- Task Functions ---
def task_kyber():
    with oqs.KeyEncapsulation("ML-KEM-768") as k:
        pk = k.generate_keypair()
        ct, ss = k.encap_secret(pk)
        k.decap_secret(ct)

def task_dilithium():
    with oqs.Signature("ML-DSA-65") as s:
        pk = s.generate_keypair()
        msg = b"msg"
        sig = s.sign(msg)
        s.verify(msg, sig, pk)

def task_rsa():
    enc = rsa_cipher.encrypt(rsa_msg)
    rsa_cipher.decrypt(enc)

def task_ecc():
    # X25519 (KeyGen + Agree) + ECDSA (Sign + Verify)
    k = ECC.generate(curve='X25519'); k.public_key()
    signer.sign(hasher)
    verifier.verify(hasher, sig_ecc)

# --- EXECUTE MEASUREMENT ---
t_kyber_cpu = measure_avg(task_kyber, "Kyber768")
t_dilithium_cpu = measure_avg(task_dilithium, "Dilithium3")
t_rsa_cpu = measure_avg(task_rsa, "RSA-3072")
t_ecc_cpu = measure_avg(task_ecc, "ECC TLS1.3")

# ==============================================================================
# 3. TỔNG HỢP DỮ LIỆU CHO 5 GIAO THỨC
# ==============================================================================
print("\n--- [BƯỚC 2] MÔ PHỎNG MẠNG VÀ TẠO BOXPLOT ---")

protocols = [
    'Kyber-only',           # 0
    'TLS 1.3\n(Classical)', # 1
    'Hybrid TLS\n(Dilithium)', # 2
    'KEMTLS',               # 3
    'HPQ-AKE\n(Ours)'       # 4
]

# 1. Tính Size (Bytes)
s_kyber = SIZES["Kyber768_PK"] + SIZES["Kyber768_CT"] + SIZES["OH_KyberOnly"]
s_tls   = SIZES["X25519_PK"]*2 + SIZES["ECDSA_SIG"] + SIZES["OH_TLS13"]
s_hyb   = SIZES["Kyber768_CT"] + SIZES["Dilithium3_SIG"] + SIZES["OH_Hybrid"]
s_kem   = SIZES["Kyber768_CT"]*2 + SIZES["OH_KEMTLS"]
s_hpq   = SIZES["Kyber768_CT"] + SIZES["RSA3072_CT"] + SIZES["OH_HPQ"]

sizes = [s_kyber, s_tls, s_hyb, s_kem, s_hpq]

# 2. Tính CPU Base (ms) - Từ kết quả đo thực tế
c_kyber = t_kyber_cpu
c_tls   = t_ecc_cpu
c_hyb   = t_kyber_cpu + t_dilithium_cpu
c_kem   = t_kyber_cpu * 2
c_hpq   = t_kyber_cpu + t_rsa_cpu

cpu_bases = [c_kyber, c_tls, c_hyb, c_kem, c_hpq]

# 3. Monte Carlo Simulation (Tạo dữ liệu Boxplot)
simulation_data = []
bw_bytes_ms = (NETWORK_CONFIG["Bandwidth_kbps"] * 1000) / 8 / 1000
rtt = NETWORK_CONFIG["RTT_ms"]

np.random.seed(42) # Cố định seed để kết quả ổn định khi chạy lại

for cpu, size in zip(cpu_bases, sizes):
    t_net = size / bw_bytes_ms
    samples = []
    for _ in range(10000): # 10000 mẫu thử mỗi giao thức
        # Thêm nhiễu mạng (Network Jitter) và nhiễu CPU nhẹ
        net_jitter = np.random.normal(0, (t_net + rtt) * NETWORK_CONFIG["Jitter_Percent"])
        cpu_jitter = np.random.normal(0, cpu * 0.02)
        
        total = cpu + rtt + t_net + net_jitter + cpu_jitter
        samples.append(total)
    simulation_data.append(samples)

# ==============================================================================
# 4. VẼ BIỂU ĐỒ (5 CỘT)
# ==============================================================================
fig, ax = plt.subplots(figsize=(12, 7))

# Màu sắc: Xám cho Baseline, Xanh cho KEMTLS, Đỏ cho HPQ
colors = ['#bdc3c7', '#95a5a6', '#7f8c8d', '#3498db', '#e74c3c']

bplot = ax.boxplot(simulation_data, 
                   patch_artist=True,
                   labels=protocols, # Nhãn trục X
                   showfliers=False,
                   medianprops=dict(color="black", linewidth=1.5))

# Tô màu
for patch, color in zip(bplot['boxes'], colors):
    patch.set_facecolor(color)
    patch.set_alpha(0.8)

# Trang trí trục
ax.set_title(f'End-to-End Latency Stability Analysis (5 Protocols)\nScenario: Satellite {NETWORK_CONFIG["Bandwidth_kbps"]}kbps, RTT {rtt}ms', 
             fontsize=14, fontweight='bold')
ax.set_ylabel('Total Handshake Latency (ms)', fontsize=12, fontweight='bold')
ax.yaxis.grid(True, linestyle='--', alpha=0.3)

# Hiển thị số liệu trung bình (Mean)
means = [np.mean(d) for d in simulation_data]
for i, mean in enumerate(means):
    # Đẩy text lên chút cho dễ đọc
    ax.text(i + 1, mean - 200, f'{int(mean)} ms', 
            ha='center', va='top', fontsize=10, fontweight='bold', color='black')

# --- MŨI TÊN SO SÁNH (QUAN TRỌNG) ---
# So sánh Hybrid (index 2) vs HPQ (index 4)
val_hybrid = means[2]
val_hpq = means[4]
imp = (1 - val_hpq/val_hybrid) * 100

ax.annotate(f'HPQ Faster\n{imp:.1f}%', 
            xy=(5, val_hpq),            # Trỏ vào cột 5 (HPQ)
            xytext=(5, val_hybrid),     # Text nằm ngang độ cao cột Hybrid
            arrowprops=dict(facecolor='red', arrowstyle="->", lw=2),
            ha='center', fontsize=11, fontweight='bold', color='red',
            bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="red"))

plt.tight_layout()
plt.savefig('Final_Boxplot_5Cols.png', dpi=300)
print("\n>> Đã lưu biểu đồ: Final_Boxplot_5Cols.png")
plt.show()