import numpy as np
import matplotlib.pyplot as plt

# ==============================================================================
# 1. EMPIRICAL MICROBENCHMARK RESULTS (Red Team Standardized)
# ==============================================================================

protocols = [
    'Kyber-only', 
    'TLS 1.3\n(Classical)', 
    'Hybrid TLS\n(Full)', 
    'Hybrid TLS\n(Pre-cached)', # ĐỒNG BỘ: Cột mốc đối chứng tối thượng
    'KEMTLS\nBaseline', 
    'HPQ-AKE\n(Ours)'
]

# Đồng bộ 6 cấu hình CPU (Hybrid TLS chia sẻ chung thời gian CPU)
cpu_vals = [0.0331, 2.1849, 2.3340, 2.3340, 0.0661, 3.5577]
cpu_std  = [0.0057, 0.2426, 0.2497, 0.2497, 0.0080, 0.4975]

# ==============================================================================
# 2. COMMUNICATION OVERHEAD MODEL (Đồng nhất Vũ trụ Vật lý)
# ==============================================================================
SIZES = {
    "Kyber768_PK": 1184, "Kyber768_CT": 1088,
    "Dilithium3_SIG": 3293, "Dilithium3_PK": 1952,
    "RSA3072_CT": 384, "RSA3072_PK": 384,
    "X25519_PK": 32, "ECDSA_SIG": 64,
    "OH_KyberOnly": 128, "OH_TLS13": 1628, "OH_Hybrid": 8628, "OH_KEMTLS": 7628, "OH_HPQ": 2628
}

# [FIXED LỖI TOÁN HỌC]: Cập nhật chính xác công thức cộng payload như file Monte Carlo
size_vals = [
    SIZES["Kyber768_PK"] + SIZES["Kyber768_CT"] + SIZES["OH_KyberOnly"], # Kyber-only
    SIZES["X25519_PK"] * 2 + SIZES["ECDSA_SIG"] + SIZES["OH_TLS13"],     # TLS 1.3
    SIZES["X25519_PK"] * 2 + SIZES["ECDSA_SIG"] + SIZES["Kyber768_PK"] + SIZES["Kyber768_CT"] + SIZES["Dilithium3_SIG"] + SIZES["OH_Hybrid"], # Hybrid Full (~13KB)
    6209, # Hybrid Pre-cached (RFC 7924)
    SIZES["Kyber768_PK"] * 2 + SIZES["Kyber768_CT"] * 2 + SIZES["OH_KEMTLS"], # KEMTLS (~9.8KB)
    SIZES["Kyber768_CT"] + SIZES["RSA3072_CT"] + SIZES["OH_HPQ"] # HPQ-AKE (4.1KB - Đã trừ PK do pre-cached)
]

# ==============================================================================
# 3. NETWORK RTT MODEL (The Truth Engine)
# ==============================================================================
# [SỬA LỖI CHÍ MẠNG]: KEMTLS (index 4) là 2.0 RTT, HPQ-AKE (index 5) là 1.5 RTT
rtt_factors = [1.0, 1.0, 1.0, 1.0, 2.0, 1.5]

scenarios = [
    {'name': 'Fiber / LAN\n(100 Mbps, 10 ms)', 'bw': 100, 'rtt': 10},
    {'name': '4G / Wi-Fi\n(10 Mbps, 50 ms)', 'bw': 10, 'rtt': 50},
    {'name': 'Satellite / IoT\n(50 kbps, 600 ms)', 'bw': 0.05, 'rtt': 600} 
]

colors = ['#bdc3c7', '#7f8c8d', '#95a5a6', '#9b59b6', '#3498db', '#e74c3c']
plt.rcParams['font.family'] = 'DejaVu Sans'

# ==============================================================================
# FIGURE 1: TRADE-OFF 
# ==============================================================================
fig1, ax1 = plt.subplots(figsize=(13, 6))
x = np.arange(len(protocols))

bars = ax1.bar(x, size_vals, color=colors, alpha=0.75, width=0.6)
ax1.set_ylabel('Communication Overhead (Bytes)', fontsize=12, fontweight='bold')
ax1.set_xticks(x); ax1.set_xticklabels(protocols)
ax1.set_ylim(0, max(size_vals) * 1.25)

for bar in bars:
    ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 150, f'{int(bar.get_height())}', ha='center', fontsize=10, fontweight='bold')

ax2 = ax1.twinx()
ax2.errorbar(x, cpu_vals, yerr=cpu_std, color='#2c3e50', marker='D', linewidth=2, markersize=8, capsize=5)
ax2.set_ylabel('CPU Processing Time (ms)', fontsize=12, fontweight='bold', color='#2c3e50')
ax2.set_ylim(0, max(cpu_vals) * 1.3)

for i, v in enumerate(cpu_vals):
    ax2.annotate(f'{v:.2f} ms', (i, v), xytext=(0, 10), textcoords='offset points', ha='center', fontsize=9, fontweight='bold', color='#2c3e50', bbox=dict(boxstyle='round,pad=0.25', fc='white', alpha=0.9))

plt.title('Performance Trade-off: Computation vs Communication', fontsize=15, fontweight='bold')
plt.tight_layout()
plt.savefig('Chart1_TradeOff_True.png', dpi=300, bbox_inches='tight')

# ==============================================================================
# FIGURE 2: NETWORK LATENCY (Physics Compliant with MTU Fragmentation)
# ==============================================================================
fig2, axes = plt.subplots(1, 3, figsize=(18, 6))
fig2.suptitle('End-to-End Handshake Latency Across Network Environments', fontsize=16, fontweight='bold', y=1.03)

MTU_PAYLOAD = 1460 
TCP_IP_HEADER_SIZE = 40

for i, ax in enumerate(axes):
    scenario = scenarios[i]
    bw_bytes_ms = (scenario['bw'] * 1e6) / 8 / 1000
    latencies = []

    for cpu, size, rtt_f in zip(cpu_vals, size_vals, rtt_factors):
        # MTU Fragmentation Model
        num_packets = np.ceil(size / MTU_PAYLOAD)
        total_wire_size = size + (num_packets * TCP_IP_HEADER_SIZE) 
        
        trans_delay = total_wire_size / bw_bytes_ms
        total_latency = cpu + (scenario['rtt'] * rtt_f) + trans_delay
        latencies.append(total_latency)

    bars = ax.bar(protocols, latencies, color=colors, alpha=0.9, width=0.6)
    
    ax.set_title(scenario['name'], fontsize=12, fontweight='bold')
    ax.set_ylabel('Total Handshake Latency (ms)', fontweight='bold')
    ax.grid(axis='y', linestyle='--', alpha=0.3)
    ax.set_xticks(range(len(protocols)))
    ax.set_xticklabels(protocols, rotation=45, ha='right')
    ax.set_ylim(0, max(latencies) * 1.25)

    for bar in bars:
        h = bar.get_height()
        txt = f'{h:.1f}' if h < 100 else f'{int(h)}'
        ax.text(bar.get_x() + bar.get_width()/2, h, txt, ha='center', va='bottom', fontsize=9, fontweight='bold')

    # [INDEX ALIGNED]: So sánh HPQ-AKE (index 5) với Hybrid Pre-cached (index 3)
    if i == 2:
        lat_hybrid_cached = latencies[3]
        lat_hpq = latencies[5]
        improvement = (1 - lat_hpq / lat_hybrid_cached) * 100
        
        ax.annotate(f'HPQ-AKE\n{improvement:.1f}% Faster', xy=(5, lat_hpq), xytext=(3.5, lat_hybrid_cached * 0.95),
                    arrowprops=dict(arrowstyle='->', lw=2.5, color='darkred', connectionstyle='arc3,rad=-0.15'),
                    ha='center', fontsize=11, fontweight='bold', color='darkred',
                    bbox=dict(boxstyle='round,pad=0.3', fc='white', ec='darkred'))

plt.tight_layout()
plt.savefig('Chart2_NetworkLatency_True.png', dpi=300, bbox_inches='tight')
print(">> Execution Complete. Physical Universe (6 Configurations, MTU, RTT) Fully Synchronized.")
plt.show()