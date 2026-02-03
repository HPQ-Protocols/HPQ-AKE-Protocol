import matplotlib.pyplot as plt
import numpy as np

# --- 1. Cấu hình dữ liệu ---
# Kích thước chuyển đổi sang bits (1 KB = 1024 * 8 bits)
size_tls_bits = 13.0 * 1024 * 8 
size_hpq_bits = 4.1 * 1024 * 8

# Thời gian xử lý CPU (miliseconds)
t_cpu_tls = 0.1 
t_cpu_hpq = 3.5 

# Dải băng thông từ 64 kbps đến 100,000 kbps (100 Mbps)
bw_kbps = np.geomspace(64, 100000, 1000)

# --- 2. Hàm tính toán độ trễ ---
def calc_latency(size_bits, t_cpu, bandwidth_kbps):
    # Bandwidth kbps -> bits per ms: (bw * 1000) / 1000 = bw
    t_trans = size_bits / bandwidth_kbps
    return t_cpu + t_trans

latency_tls = calc_latency(size_tls_bits, t_cpu_tls, bw_kbps)
latency_hpq = calc_latency(size_hpq_bits, t_cpu_hpq, bw_kbps)

# --- 3. Vẽ biểu đồ ---
plt.figure(figsize=(8, 5))
plt.plot(bw_kbps, latency_tls, label='Hybrid TLS 1.3 (Kyber+Dilithium)', color='red', linestyle='--')
plt.plot(bw_kbps, latency_hpq, label='HPQ-AKE (Proposed)', color='blue', linewidth=2)

# Tô màu vùng lợi thế của HPQ-AKE
plt.fill_between(bw_kbps, latency_tls, latency_hpq, where=(latency_hpq < latency_tls), 
                 color='green', alpha=0.1, label='HPQ-AKE Advantage Zone')

# Cấu hình trục tọa độ Logarith (chuẩn IEEE cho dải dữ liệu rộng)
plt.xscale('log')
plt.yscale('log')

# Chú thích các điểm quan trọng
plt.axvline(x=21444, color='black', linestyle=':', alpha=0.5)
plt.text(25000, 10, 'Break-even: 21.4 Mbps', fontsize=9, fontweight='bold')

plt.xlabel('Bandwidth (kbps)')
plt.ylabel('Total Latency (ms)')
plt.title('Break-even Analysis: HPQ-AKE vs. Hybrid TLS 1.3')
plt.legend()
plt.grid(True, which="both", ls="-", alpha=0.2)

# Lưu file để chèn vào LaTeX
plt.tight_layout()
plt.savefig('break_even_plot.pdf') # Lưu định dạng PDF để không bị vỡ nét trong LaTeX
plt.show()