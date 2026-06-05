import matplotlib.pyplot as plt
import numpy as np

# ==============================================================================
# 1. STANDARDIZED EMPIRICAL DATA (ĐỐI CHỨNG CÔNG BẰNG TUYỆT ĐỐI)
# ==============================================================================
CPU_RESULTS = {
    "Hybrid_TLS": 2.3340,   # Chung CPU cho cả Full và Pre-cached
    "HPQ_AKE": 3.5577       
}

# [FIXED RED TEAM]: Bắt buộc so sánh với cấu hình TLS đã tối ưu hóa lưu kho (Pre-cached)
SIZE_BYTES = {
    "Hybrid_TLS_Cached": 6209,  # Không còn dùng 13009 nữa!
    "HPQ_AKE": 4100
}

t_cpu_tls = CPU_RESULTS["Hybrid_TLS"]
t_cpu_hpq = CPU_RESULTS["HPQ_AKE"]

# Cấu hình mạng kiểm thử mạng diện rộng tiêu chuẩn công nghiệp (Ví dụ 4G/WAN)
RTT_MS = 20.0 
bw_kbps_range = np.geomspace(64, 150000, 2500)

# ==============================================================================
# 2. PHYSICS-COMPLIANT LATENCY MODEL (TÍCH HỢP MTU FRAGMENTATION)
# ==============================================================================
MTU_PAYLOAD = 1460
TCP_IP_HEADER = 40

def get_wire_size_bits(size_bytes):
    """Tính toán dung lượng thực tế đẩy lên đường truyền sau khi phân mảnh MTU"""
    num_packets = np.ceil(size_bytes / MTU_PAYLOAD)
    return (size_bytes + (num_packets * TCP_IP_HEADER)) * 8

wire_tls_bits = get_wire_size_bits(SIZE_BYTES["Hybrid_TLS_Cached"])
wire_hpq_bits = get_wire_size_bits(SIZE_BYTES["HPQ_AKE"])

def calc_latency(wire_bits, cpu_ms, bandwidth_kbps, rtt_ms, rtt_mult):
    transmission_ms = wire_bits / bandwidth_kbps
    return transmission_ms + cpu_ms + (rtt_ms * rtt_mult)

y_tls = calc_latency(wire_tls_bits, t_cpu_tls, bw_kbps_range, RTT_MS, rtt_mult=1.0)
y_hpq = calc_latency(wire_hpq_bits, t_cpu_hpq, bw_kbps_range, RTT_MS, rtt_mult=1.5)

# ==============================================================================
# 3. BREAK-EVEN ANALYTICAL COMPUTATION (Toán học giải tích)
# Equation: wire_tls/bw + cpu_tls + RTT*1.0 = wire_hpq/bw + cpu_hpq + RTT*1.5
# ==============================================================================
delta_wire_bits = wire_tls_bits - wire_hpq_bits
delta_fixed_overhead = (t_cpu_hpq - t_cpu_tls) + (0.5 * RTT_MS)

break_even_kbps = delta_wire_bits / delta_fixed_overhead
break_even_mbps = break_even_kbps / 1000.0
y_intersection = calc_latency(wire_tls_bits, t_cpu_tls, break_even_kbps, RTT_MS, rtt_mult=1.0)

# ==============================================================================
# 4. GRAPHICAL REPRESENTATION
# ==============================================================================
plt.figure(figsize=(11, 6.5))
plt.plot(bw_kbps_range / 1000.0, y_tls, label='Hybrid TLS 1.3 (Pre-cached, RFC 7924)', color='#9b59b6', lw=2.5) # Đổi sang màu tím đồng bộ
plt.plot(bw_kbps_range / 1000.0, y_hpq, label='HPQ-AKE (Ours: Sign-Less Dual KEM)', color='#2ecc71', lw=2.5)

# Đánh dấu giao điểm cấu trúc đường thẳng
plt.plot(break_even_mbps, y_intersection, marker='o', markersize=8, color='black', zorder=5)
plt.text(break_even_mbps * 1.2, y_intersection * 1.08, f'Break-even Point\n{break_even_mbps:.2f} Mbps',
         fontsize=10, fontweight='bold', bbox=dict(boxstyle="round,pad=0.35", fc="white", ec="#7f8c8d", alpha=0.95))

# Đánh giá cải tiến cụ thể tại vùng băng thông thấp (100 kbps)
satellite_bw = 100 # kbps
satellite_tls = calc_latency(wire_tls_bits, t_cpu_tls, satellite_bw, RTT_MS, rtt_mult=1.0)
satellite_hpq = calc_latency(wire_hpq_bits, t_cpu_hpq, satellite_bw, RTT_MS, rtt_mult=1.5)
improvement = (1 - (satellite_hpq / satellite_tls)) * 100

plt.annotate(f'Low-bandwidth Advantage\nHPQ-AKE ≈ {improvement:.1f}% Faster', 
             xy=(satellite_bw / 1000.0, satellite_hpq), xytext=(0.5, satellite_tls * 0.7),
             arrowprops=dict(arrowstyle='->', lw=2, color='darkgreen'), fontsize=10, fontweight='bold', color='darkgreen',
             bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="darkgreen"))

plt.xscale('log')
plt.yscale('log')
plt.title('Handshake Latency Break-Even Analysis (MTU-Aware, Pre-cached Baseline)', fontsize=13, fontweight='bold')
plt.xlabel('Network Bandwidth (Mbps)', fontsize=11, fontweight='bold')
plt.ylabel('Total Handshake Latency (ms)', fontsize=11, fontweight='bold')
plt.legend(loc='upper right', frameon=True, facecolor='white', edgecolor='none')
plt.grid(True, which="both", linestyle='--', alpha=0.4)

plt.tight_layout()
plt.show()