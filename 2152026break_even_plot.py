import matplotlib.pyplot as plt
import numpy as np

# ==============================================================================
# 1. CẤU HÌNH DỮ LIỆU KHỚP CHÍNH XÁC VỚI BẢN THẢO BÀI BÁO
# ==============================================================================
# Sử dụng CHÍNH XÁC số lượng Bytes công bố tại Abstract và Section 6.2.3
size_tls_bytes = 13009  # Bản thảo: 13,009 Bytes
size_hpq_bytes = 4100   # Bản thảo: 4,100 Bytes

size_tls_bits = size_tls_bytes * 8
size_hpq_bits = size_hpq_bytes * 8

# Thời gian xử lý CPU (ms) - Nên lấy từ kết quả thực tế của Phần 1 (Hình 2)
t_cpu_tls = 0.1   # Tổng thời gian xử lý của Hybrid TLS 1.3
t_cpu_hpq = 3.5   # Tổng thời gian xử lý của HPQ-AKE (Kyber + RSA-OAEP)

# Độ trễ khứ hồi nền (RTT Baseline) cho môi trường mạng có dây tiêu chuẩn (ms)
# Vì cả hai đều là giao thức 1-RTT trong kịch bản này nên RTT không làm thay đổi 
# vị trí điểm hòa vốn nhưng giúp đồ thị không bị tiệm cận về 0 ms (phi vật lý).
rtt_baseline = 20.0 

# Dải băng thông từ 64 kbps đến 100,000 kbps (100 Mbps)
bw_kbps = np.geomspace(64, 100000, 1000)

# ==============================================================================
# 2. HÀM TÍNH TOÁN ĐỘ TRỄ HANDSHAKE
# ==============================================================================
def calc_latency(size_bits, t_cpu, bandwidth_kbps, rtt):
    # bandwidth_kbps tương đương số bits truyền được trong 1 ms vì:
    # (kbps * 1000 bits/s) / (1000 ms/s) = kbps bits/ms
    t_trans = size_bits / bandwidth_kbps
    return t_cpu + rtt + t_trans

latency_tls = calc_latency(size_tls_bits, t_cpu_tls, bw_kbps, rtt_baseline)
latency_hpq = calc_latency(size_hpq_bits, t_cpu_hpq, bw_kbps, rtt_baseline)

# ==============================================================================
# 3. TỰ ĐỘNG TÍNH TOÁN ĐIỂM HÒA VỐN (BREAK-EVEN POINT) THEO TOÁN HỌC
# ==============================================================================
# Công thức giải tích từ phương trình cân bằng: Latency_TLS = Latency_HPQ
# t_cpu_tls + RTT + (size_tls / BW) = t_cpu_hpq + RTT + (size_hpq / BW)
# => BW_kbps = (size_tls_bits - size_hpq_bits) / (t_cpu_hpq - t_cpu_tls)
break_even_kbps = (size_tls_bits - size_hpq_bits) / (t_cpu_hpq - t_cpu_tls)
break_even_mbps = break_even_kbps / 1000  # Đổi sang Mbps để hiển thị nhãn

print(f">> Giao điểm hòa vốn được tính toán tự động: {break_even_kbps:.2f} kbps ({break_even_mbps:.2f} Mbps)")

# ==============================================================================
# 4. VẼ BIỂU ĐỒ CHUẨN ĐỒ HỌA HỌC THUẬT (IEEE/ELSEVIER STYLE)
# ==============================================================================
plt.figure(figsize=(9, 5.5))

# Vẽ 2 đường cong hiệu năng
plt.plot(bw_kbps, latency_tls, label='Hybrid TLS 1.3 (Kyber+Dilithium)', color='#e74c3c', linestyle='--', linewidth=2)
plt.plot(bw_kbps, latency_hpq, label='HPQ-AKE (Our Proposed Sign-Less)', color='#2c3e50', linewidth=2.5)

# Tô màu vùng lợi thế của giao thức đề xuất HPQ-AKE
plt.fill_between(bw_kbps, latency_tls, latency_hpq, where=(latency_hpq < latency_tls), 
                 color='#2ecc71', alpha=0.15, label='HPQ-AKE Advantage Domain')

# Sử dụng thang đo Logarith cho cả 2 trục (Bắt buộc đối với dải dữ liệu động lớn)
plt.xscale('log')
plt.yscale('log')

# Vẽ đường giới hạn điểm hòa vốn tự động (Tuyệt đối không gán cứng số)
plt.axvline(x=break_even_kbps, color='#7f8c8d', linestyle=':', linewidth=1.5, alpha=0.8)

# Định vị nhãn hiển thị điểm hòa vốn tự động dựa trên giao điểm tọa độ
y_text_pos = calc_latency(size_tls_bits, t_cpu_tls, break_even_kbps, rtt_baseline)
plt.plot(break_even_kbps, y_text_pos, marker='o', color='black', markersize=6) # Đánh dấu chấm đen tại giao điểm

plt.text(break_even_kbps * 1.2, y_text_pos * 1.1, f'Break-even Point:\n{break_even_mbps:.2f} Mbps', 
         fontsize=10, fontweight='bold', color='#2c3e50',
         bbox=dict(boxstyle="round,pad=0.3", fc="#f8f9fa", ec="#bdc3c7", alpha=0.9))

# Cấu hình nhãn trục và tiêu đề theo chuẩn tiếng Anh học thuật
plt.xlabel('Available Bandwidth (kbps)', fontsize=11, fontweight='bold', labelpad=8)
plt.ylabel('Total Handshake Latency (ms)', fontsize=11, fontweight='bold', labelpad=8)
plt.title('Break-even Analysis: Latency vs. Bandwidth Sensitivity', fontsize=13, fontweight='bold', pad=15)

plt.legend(loc='upper right', frameon=True, facecolor='white', edgecolor='#ebdcb9', fontsize=10)
plt.grid(True, which="both", linestyle="--", alpha=0.4)

# Tối ưu hóa khoảng trống và xuất file vector PDF độ nét cao cho LaTeX
plt.tight_layout()
plt.savefig('Figure5_BreakEvenAnalysis.pdf', dpi=300)
print(">> Đã xuất file thành công: Figure5_BreakEvenAnalysis.pdf")
plt.show()