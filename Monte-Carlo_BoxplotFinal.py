import oqs
import time
import numpy as np
import matplotlib.pyplot as plt

# ==============================================================================
# 1. EMPIRICAL + ANALYTICAL CONFIGURATION
# ==============================================================================
SIZES = {
    "Kyber768_PK": 1184, "Kyber768_CT": 1088,
    "Dilithium3_SIG": 3293, "Dilithium3_PK": 1952,
    "RSA3072_CT": 384, "RSA3072_PK": 384,
    "X25519_PK": 32, "ECDSA_SIG": 64,
    "OH_KyberOnly": 128,  
    "OH_TLS13": 1628,     
    "OH_Hybrid": 8628,    
    "OH_KEMTLS": 7628,    
    "OH_HPQ": 2628        
}

NETWORK_CONFIG = {
    "Bandwidth_kbps": 50,  
    "RTT_ms": 600,
    "Jitter_Percent": 0.12
}

CPU_MEANS = [0.0331, 2.1849, 2.3340, 2.3340, 0.0661, 3.5577] 
CPU_STDS  = [0.0057, 0.2426, 0.2497, 0.2497, 0.0080, 0.4975]

# [FIXED LỖI CHÍ MẠNG]: Trả lại đúng dung lượng thật sự của HPQ-AKE (4100 Bytes)
bytes_kyber = SIZES["Kyber768_PK"] + SIZES["Kyber768_CT"] + SIZES["OH_KyberOnly"]
bytes_tls = SIZES["X25519_PK"]*2 + SIZES["ECDSA_SIG"] + SIZES["OH_TLS13"]
bytes_hybrid = SIZES["X25519_PK"]*2 + SIZES["ECDSA_SIG"] + SIZES["Kyber768_PK"] + SIZES["Kyber768_CT"] + SIZES["Dilithium3_SIG"] + SIZES["OH_Hybrid"]
bytes_hybrid_cached = 6209 # RFC 7924
bytes_kemtls = SIZES["Kyber768_PK"]*2 + SIZES["Kyber768_CT"]*2 + SIZES["OH_KEMTLS"]

# Sửa lại: Không cộng PK vì giao thức thiết kế là Pre-cached
bytes_hpq = SIZES["Kyber768_CT"] + SIZES["RSA3072_CT"] + SIZES["OH_HPQ"]

PROTOCOL_SIZES = [bytes_kyber, bytes_tls, bytes_hybrid, bytes_hybrid_cached, bytes_kemtls, bytes_hpq]
RTT_MULTIPLIERS = [1.0, 1.0, 1.0, 1.0, 2.0, 1.5] 

protocols = [
    'Kyber-only', 
    'TLS 1.3\n(Classical)', 
    'Hybrid TLS\n(Full)', 
    'Hybrid TLS\n(Pre-cached)', 
    'KEMTLS Baseline', 
    'HPQ-AKE\n(Ours)'
]

# ==============================================================================
# 2. RIGOROUS MONTE CARLO (WITH MTU FRAGMENTATION & EXPONENTIAL JITTER)
# ==============================================================================
np.random.seed(42)
N_SIMULATIONS = 5000
simulation_data = []

MTU_PAYLOAD = 1460
TCP_IP_HEADER = 40

for idx in range(len(protocols)):
    size_bytes = PROTOCOL_SIZES[idx]
    bw_kbps = NETWORK_CONFIG["Bandwidth_kbps"]
    rtt_base = NETWORK_CONFIG["RTT_ms"] * RTT_MULTIPLIERS[idx]
    
    # [ĐỒNG BỘ VẬT LÝ]: Thêm thuật toán phân mảnh gói tin (MTU)
    num_packets = np.ceil(size_bytes / MTU_PAYLOAD)
    total_wire_bits = (size_bytes + (num_packets * TCP_IP_HEADER)) * 8
    
    transmission_delay = total_wire_bits / bw_kbps
    base_delay = transmission_delay + rtt_base
    
    cpu_samples = np.random.normal(CPU_MEANS[idx], CPU_STDS[idx], N_SIMULATIONS)
    jitter_samples = np.random.exponential(scale=base_delay * NETWORK_CONFIG["Jitter_Percent"], size=N_SIMULATIONS)
    
    total_network_delay = base_delay + jitter_samples
    total_handshake_latency = cpu_samples + total_network_delay
    simulation_data.append(total_handshake_latency)

# ==============================================================================
# 3. HIGH-QUALITY PLOTTING
# ==============================================================================
fig, ax = plt.subplots(figsize=(13, 7))
colors = ['#95a5a6', '#3498db', '#e74c3c', '#9b59b6', '#e67e22', '#2ecc71']

bp = ax.boxplot(simulation_data, tick_labels=protocols, patch_artist=True, showmeans=False, 
                boxprops=dict(linewidth=1.5), whiskerprops=dict(linewidth=1.5), capprops=dict(linewidth=1.5))

medians = [np.median(d) for d in simulation_data]
for patch, color in zip(bp['boxes'], colors):
    patch.set_facecolor(color)
    patch.set_alpha(0.80)

means = [np.mean(d) for d in simulation_data]
stds = [np.std(d) for d in simulation_data]

ax.errorbar(range(1, len(protocols)+1), means, yerr=stds, fmt='o', color='black', capsize=5, label='Mean ± Std')
ax.set_title(f'Rigorous Monte Carlo End-to-End Latency Model (MTU aware + Exponential Jitter)\nSatellite / IoT Scenario ({NETWORK_CONFIG["Bandwidth_kbps"]} kbps, RTT={NETWORK_CONFIG["RTT_ms"]} ms)', fontsize=13, fontweight='bold')
ax.set_ylabel('Total Handshake Latency (ms)', fontsize=12, fontweight='bold')
ax.grid(axis='y', linestyle='--', alpha=0.3)

for i, median in enumerate(medians):
    ax.text(i + 1, median + (max(medians)*0.02), f'{int(median)} ms', ha='center', va='bottom', fontsize=9, fontweight='bold')

# So sánh HPQ-AKE (index 5) và Hybrid TLS Pre-cached (index 3)
hybrid_cached_val = medians[3]
hpq_val = medians[5]
improvement = (1 - hpq_val / hybrid_cached_val) * 100

ax.annotate(f'HPQ-AKE vs Pre-cached Baseline\n{improvement:.1f}% Faster', 
             xy=(6, hpq_val), xytext=(3.5, hybrid_cached_val * 1.15),
             arrowprops=dict(arrowstyle='->', lw=2.5, color='darkgreen'), 
             fontsize=11, fontweight='bold', color='darkgreen',
             bbox=dict(boxstyle="round,pad=0.4", fc="white", ec="darkgreen", alpha=0.9))

plt.tight_layout()
plt.show()