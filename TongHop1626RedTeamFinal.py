import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import oqs
from cryptography.hazmat.primitives.asymmetric import x25519
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP

# ==============================================================================
# 1. CẤU HÌNH THAM SỐ TOÀN CỤC CHUẨN XÁC (RED TEAM VALIDATED)
# ==============================================================================
PROTOCOLS = [
    'Kyber-only\nBaseline', 
    'TLS 1.3\n(Classical)', 
    'Hybrid TLS\n(Full)', 
    'Hybrid TLS\n(Pre-cached)', 
    'KEMTLS\nBaseline', 
    'HPQ-AKE\n(Ours)'
]

CPU_VALS = [0.0331, 2.1849, 2.3340, 2.3340, 0.0661, 7.1053]
CPU_STD  = [0.0057, 0.2426, 0.2497, 0.2497, 0.0080, 0.7036]

PROTOCOL_SIZES_BYTES = [
    2400,   # Kyber-only Baseline
    1756,   # TLS 1.3 (Classical)
    13009,  # Hybrid TLS 1.3 (Full Handshake phình to)
    6209,   # Hybrid TLS 1.3 (Pre-cached)
    12172,  # KEMTLS Baseline
    5284    # HPQ-AKE (Ours)
]

RTT_FACTORS = [1.0, 1.0, 1.0, 1.0, 2.0, 1.5]

MTU_PAYLOAD = 1460
TCP_IP_HEADER = 40

def get_wire_size_bits(size_bytes):
    num_packets = np.ceil(size_bytes / MTU_PAYLOAD)
    return (size_bytes + num_packets * TCP_IP_HEADER) * 8

def calc_latency(wire_bits, t_cpu, bw_kbps, rtt_ms, rtt_mult=1.0):
    t_trans = wire_bits / (bw_kbps * 1000.0) * 1000.0
    t_prop = rtt_ms * rtt_mult
    return t_cpu + t_trans + t_prop

# ==============================================================================
# MODULE 1: KIỂM THỬ VI ĐO (MICROBENCHMARK) PHẦN CỨNG THỰC TẾ
# ==============================================================================
def run_microbenchmarks():
    print("\n" + "="*80)
    print(" MODULE 1: EXECUTING CRYPTOGRAPHIC MICROBENCHMARKS (LIVE SAMPLES)")
    print("="*80)
    
    def now_ms(): return time.perf_counter_ns() / 1e6
    def compute_stats(samples):
        arr = np.array(samples)
        return {"mean": np.mean(arr), "std": np.std(arr, ddof=1)}
        
    ITERATIONS = 50
    print(f"Đang lấy mẫu thực nghiệm mật mã ({ITERATIONS} vòng)... Vui lòng đợi.")
    
    # --- PQC KEM: ML-KEM-768 ---
    kyber = oqs.KeyEncapsulation("Kyber768")
    k_pk = kyber.generate_keypair()
    
    ts = [0.0] * ITERATIONS
    for i in range(ITERATIONS): 
        t_start = now_ms()
        kyber.generate_keypair()
        ts[i] = now_ms() - t_start
    k_kg_stat = compute_stats(ts)
    
    ts = [0.0] * ITERATIONS
    for i in range(ITERATIONS): 
        t_start = now_ms()
        kyber.encap_secret(k_pk) 
        ts[i] = now_ms() - t_start
    k_enc_stat = compute_stats(ts)
    k_ct, k_ss = kyber.encap_secret(k_pk)
    
    ts = [0.0] * ITERATIONS
    for i in range(ITERATIONS): 
        t_start = now_ms()
        kyber.decap_secret(k_ct) 
        ts[i] = now_ms() - t_start
    k_dec_stat = compute_stats(ts)
    kyber.free()

    # --- Classic KEM: RSA-3072 (OAEP) ---
    rsa_key = RSA.generate(3072)
    rsa_pub = rsa_key.publickey()
    cipher_enc = PKCS1_OAEP.new(rsa_pub)
    cipher_dec = PKCS1_OAEP.new(rsa_key)
    secret_payload = b"A"*32
    
    ts = [0.0] * ITERATIONS
    for i in range(ITERATIONS): 
        t_start = now_ms()
        cipher_enc.encrypt(secret_payload)
        ts[i] = now_ms() - t_start
    r_enc_stat = compute_stats(ts)
    enc_msg = cipher_enc.encrypt(secret_payload)
    
    ts = [0.0] * ITERATIONS
    for i in range(ITERATIONS): 
        t_start = now_ms()
        cipher_dec.decrypt(enc_msg)
        ts[i] = now_ms() - t_start
    r_dec_stat = compute_stats(ts)

    df_components = pd.DataFrame({
        "Component Primitive": ["Kyber768 KeyGen", "Kyber768 Encaps", "Kyber768 Decaps", "RSA-3072 Encrypt", "RSA-3072 Decrypt"],
        "Mean Latency (ms)": [k_kg_stat['mean'], k_enc_stat['mean'], k_dec_stat['mean'], r_enc_stat['mean'], r_dec_stat['mean']],
        "Std Dev (ms)": [k_kg_stat['std'], k_enc_stat['std'], k_dec_stat['std'], r_enc_stat['std'], r_dec_stat['std']]
    })
    print("\n[BẢNG THÔNG SỐ VI ĐO TRÊN PHẦN CỨNG THỰC TẾ]:")
    print(df_components.to_string(index=False))

# ==============================================================================
# MODULE 1.5: VẼ ĐỒ THỊ ĐÁNH ĐỔI (TRADE-OFF) DUNG LƯỢNG MẠNG VÀ THỜI GIAN CPU
# ==============================================================================
def plot_tradeoff_chart():
    print("\n" + "="*80)
    print(" MODULE 1.5: GENERATING COMPUTATION VS COMMUNICATION TRADE-OFF CHART")
    print("="*80)
    
    fig, ax1 = plt.subplots(figsize=(12, 6.5))
    x = np.arange(len(PROTOCOLS))
    colors = ['#bdc3c7', '#2980b9', '#e74c3c', '#d35400', '#8e44ad', '#27ae60']
    
    bars = ax1.bar(x, PROTOCOL_SIZES_BYTES, color=colors, alpha=0.85, width=0.6)
    ax1.set_ylabel('Total Communication Overhead (Bytes)', fontsize=12, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(PROTOCOLS, rotation=0, fontsize=10)
    ax1.set_ylim(0, max(PROTOCOL_SIZES_BYTES) * 1.25)
    ax1.grid(axis='y', linestyle='--', alpha=0.3)
    
    for bar in bars:
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 200, 
                 f'{int(bar.get_height())}', ha='center', fontsize=11, fontweight='bold')
    
    ax2 = ax1.twinx()
    ax2.errorbar(x, CPU_VALS, yerr=CPU_STD, color='#2c3e50', marker='D', 
                 linewidth=2.5, markersize=8, capsize=5, label='CPU Processing Time')
    ax2.set_ylabel('Total CPU Processing Time (ms)', fontsize=12, fontweight='bold', color='#2c3e50')
    ax2.set_ylim(0, max(CPU_VALS) * 1.35)
    
    for i, v in enumerate(CPU_VALS):
        ax2.annotate(f'{v:.2f} ms', (i, v), xytext=(0, 15), textcoords='offset points', 
                     ha='center', fontsize=10, fontweight='bold', color='#2c3e50', 
                     bbox=dict(boxstyle='round,pad=0.3', fc='white', alpha=0.9, ec='#2c3e50'))
                     
    plt.title('Performance Trade-off: Computation Cost vs. Communication Overhead', fontsize=14, fontweight='bold')
    plt.tight_layout()
    filename = "chart1_tradeoff_analysis_FN.png"
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[THÀNH CÔNG]: Đã lưu đồ thị Trade-off tại: '{filename}'")

# ==============================================================================
# MODULE 2: ĐỒ THỊ SO SÁNH 3 KỊCH BẢN MẠNG TIÊU CHUẨN (Đã bỏ Textbox So sánh)
# ==============================================================================
def plot_network_scenarios():
    print("\n" + "="*80)
    print(" MODULE 2: GENERATING MULTI-SCENARIO NETWORK LATENCY BAR GRAPH")
    print("="*80)
    
    scenarios = [
        {"name": "Scenario A: High-Speed LAN\n(1 Gbps, RTT = 1 ms)", "bw": 1000000, "rtt": 1.0},
        {"name": "Scenario B: Standard 4G / WAN\n(25 Mbps, RTT = 40 ms)", "bw": 25000, "rtt": 40.0},
        {"name": "Scenario C: Narrowband Satellite / IoT\n(50 kbps, RTT = 600 ms)", "bw": 50, "rtt": 600.0}
    ]
    
    fig, axes = plt.subplots(1, 3, figsize=(16, 5.5))
    colors = ['#bdc3c7', '#2980b9', '#e74c3c', '#d35400', '#8e44ad', '#27ae60']
    
    for i, scenario in enumerate(scenarios):
        ax = axes[i]
        latencies = []
        for j in range(len(PROTOCOLS)):
            w_bits = get_wire_size_bits(PROTOCOL_SIZES_BYTES[j])
            lat = calc_latency(w_bits, CPU_VALS[j], scenario['bw'], scenario['rtt'], RTT_FACTORS[j])
            latencies.append(lat)
            
        bars = ax.bar(PROTOCOLS, latencies, color=colors, alpha=0.9, width=0.6)
        ax.set_title(scenario['name'], fontsize=11, fontweight='bold')
        ax.set_ylabel('Total Handshake Latency (ms)', fontweight='bold', fontsize=9)
        ax.grid(axis='y', linestyle='--', alpha=0.3)
        ax.set_xticks(range(len(PROTOCOLS)))
        ax.set_xticklabels(PROTOCOLS, rotation=45, ha='right', fontsize=9)
        ax.set_ylim(0, max(latencies) * 1.25)
        
        for bar in bars:
            h = bar.get_height()
            txt = f'{h:.1f}' if h < 100 else f'{int(h)}'
            ax.text(bar.get_x() + bar.get_width()/2, h, txt, ha='center', va='bottom', fontsize=9, fontweight='bold')

    plt.suptitle("Deterministic Handshake Latency Benchmarks Across Diverse Network Topologies", fontsize=14, fontweight='bold')
    plt.tight_layout()
    filename = "chart2_latency_scenarios_FN.png"
    plt.savefig(filename, dpi=300)
    plt.close()
    print(f"[THÀNH CÔNG]: Đã lưu đồ thị kịch bản mạng tại: '{filename}'")

# ==============================================================================
# MODULE 3: PHÂN TÍCH ĐIỂM HÒA VỐN BĂNG THÔNG (BREAK-EVEN POINT) - ĐÃ NÂNG CẤP
# ==============================================================================
def plot_break_even_curve():
    print("\n" + "="*80)
    print(" MODULE 3: COMPUTING AND PLOTTING BREAK-EVEN POINT ANALYSIS (DUAL BASELINES)")
    print("="*80)
    
    RTT_MS = 20.0
    bw_kbps_range = np.geomspace(64, 150000, 2500)
    
    # 1. Trích xuất cấu hình cho cả 3 đường
    wire_tls_full_bits = get_wire_size_bits(PROTOCOL_SIZES_BYTES[2]) # Hybrid TLS Full (MỚI THÊM)
    wire_tls_pre_bits = get_wire_size_bits(PROTOCOL_SIZES_BYTES[3])  # Hybrid TLS Pre-cached
    wire_hpq_bits = get_wire_size_bits(PROTOCOL_SIZES_BYTES[5])      # HPQ-AKE
    
    # 2. Tính toán dải độ trễ
    lat_tls_full_range = calc_latency(wire_tls_full_bits, CPU_VALS[2], bw_kbps_range, RTT_MS, rtt_mult=RTT_FACTORS[2])
    lat_tls_pre_range = calc_latency(wire_tls_pre_bits, CPU_VALS[3], bw_kbps_range, RTT_MS, rtt_mult=RTT_FACTORS[3])
    lat_hpq_range = calc_latency(wire_hpq_bits, CPU_VALS[5], bw_kbps_range, RTT_MS, rtt_mult=RTT_FACTORS[5])
    
    # 3. Tìm điểm giao cắt (Break-even) cho bản Pre-cached
    diff_pre = lat_hpq_range - lat_tls_pre_range
    idx_intersection_pre = np.where(np.diff(np.sign(diff_pre)))[0]
    
    # 4. Tìm điểm giao cắt (Break-even) cho bản Full (MỚI THÊM)
    diff_full = lat_hpq_range - lat_tls_full_range
    idx_intersection_full = np.where(np.diff(np.sign(diff_full)))[0]
    
    plt.figure(figsize=(10, 7)) # Mở rộng khung hình một chút cho dễ nhìn
    
    # 5. Vẽ 3 đường
    plt.plot(bw_kbps_range / 1000.0, lat_tls_full_range, label='Hybrid TLS 1.3 (Full Baseline)', color='#e74c3c', lw=2.5, linestyle=':')
    plt.plot(bw_kbps_range / 1000.0, lat_tls_pre_range, label='Hybrid TLS 1.3 (Pre-cached Baseline)', color='#d35400', lw=2.5, linestyle='--')
    plt.plot(bw_kbps_range / 1000.0, lat_hpq_range, label='HPQ-AKE (Our Proposed Sign-Less GOTO)', color='#27ae60', lw=2.5)
    
    # 6. Đánh dấu Break-even cho Pre-cached
    if len(idx_intersection_pre) > 0:
        idx = idx_intersection_pre[0]
        break_even_mbps_pre = bw_kbps_range[idx] / 1000.0
        y_intersection_pre = lat_hpq_range[idx]
        plt.plot(break_even_mbps_pre, y_intersection_pre, marker='o', markersize=8, color='black', zorder=5)
        plt.text(break_even_mbps_pre * 1.15, y_intersection_pre * 1.05, f'Break-even (Pre-cached)\n{break_even_mbps_pre:.2f} Mbps',
                 fontsize=10, fontweight='bold', bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="#d35400", alpha=0.95))
                 
    # 7. Đánh dấu Break-even cho Full (MỚI THÊM)
    if len(idx_intersection_full) > 0:
        idx_f = idx_intersection_full[0]
        break_even_mbps_full = bw_kbps_range[idx_f] / 1000.0
        y_intersection_full = lat_hpq_range[idx_f]
        plt.plot(break_even_mbps_full, y_intersection_full, marker='s', markersize=8, color='black', zorder=5)
        plt.text(break_even_mbps_full * 1.15, y_intersection_full * 0.85, f'Break-even (Full)\n{break_even_mbps_full:.2f} Mbps',
                 fontsize=10, fontweight='bold', bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="#e74c3c", alpha=0.95))
    
    # Giữ nguyên phần đánh giá Advantage vệ tinh
    satellite_bw = 100 
    satellite_tls = calc_latency(wire_tls_pre_bits, CPU_VALS[3], satellite_bw, RTT_MS, rtt_mult=RTT_FACTORS[3])
    satellite_hpq = calc_latency(wire_hpq_bits, CPU_VALS[5], satellite_bw, RTT_MS, rtt_mult=RTT_FACTORS[5])
    improvement = (1 - (satellite_hpq / satellite_tls)) * 100
    
    improvement_text = f'Low-bandwidth Advantage\nHPQ-AKE ≈ {improvement:.1f}% Faster' if improvement >= 0 else f'Low-bandwidth Advantage\nHPQ-AKE ≈ {abs(improvement):.1f}% Slower'
    arrow_color = 'darkgreen' if improvement >= 0 else 'darkred'
    
    plt.annotate(improvement_text, xy=(satellite_bw / 1000.0, satellite_hpq), xytext=(0.3, max(satellite_tls, satellite_hpq) * 0.65),
                 arrowprops=dict(arrowstyle='->', lw=2, color=arrow_color), fontsize=10, fontweight='bold', color=arrow_color,
                 bbox=dict(boxstyle="round,pad=0.3", fc="white", ec=arrow_color, alpha=0.9))
                 
    plt.xscale('log')
    plt.yscale('log')
    plt.title('Analytical Break-Even Analysis Over Bandwidth Spectrum (RTT = 20ms)', fontsize=12, fontweight='bold')
    plt.xlabel('Available Network Bandwidth (Mbps)', fontsize=11, fontweight='bold')
    plt.ylabel('Total Handshake Execution Cost (ms)', fontsize=11, fontweight='bold')
    plt.grid(True, which="both", ls="--", color='gray', alpha=0.2)
    plt.legend(loc='lower left', frameon=True, facecolor='white', framealpha=0.9)
    
    filename = "chart3_break_even_FN_Dual.png"
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[THÀNH CÔNG]: Đã lưu đồ thị phân tích điểm hòa vốn tại: '{filename}'")

# ==============================================================================
# MODULE 4: MÔ PHỎNG XÁC SUẤT MONTE CARLO VỚI JITTER MẠNG EXPONENTIAL (Đã bỏ Textbox So sánh)
# ==============================================================================
def run_monte_carlo_simulation():
    print("\n" + "="*80)
    print(" MODULE 4: EXECUTING RIGOROUS STOCHASTIC MONTE CARLO SIMULATION")
    print("="*80)
    
    NETWORK_CONFIG = {"Bandwidth_kbps": 50, "RTT_ms": 600, "Jitter_Percent": 0.12}
    NUM_SIMULATIONS = 10000
    
    np.random.seed(42)
    simulation_data = []
    
    print(f"Đang chạy mô phỏng ngẫu nhiên Monte Carlo ({NUM_SIMULATIONS} lượt)...")
    
    for i in range(len(PROTOCOLS)):
        w_size_bytes = PROTOCOL_SIZES_BYTES[i]
        num_packets = np.ceil(w_size_bytes / MTU_PAYLOAD)
        total_wire_bits = (w_size_bytes + num_packets * TCP_IP_HEADER) * 8
        
        cpu_samples = np.random.normal(CPU_VALS[i], CPU_STD[i], NUM_SIMULATIONS)
        cpu_samples = np.clip(cpu_samples, 0.001, None)
        
        base_prop_delay = NETWORK_CONFIG["RTT_ms"] * RTT_FACTORS[i]
        
        jitter_scale = base_prop_delay * NETWORK_CONFIG["Jitter_Percent"]
        network_jitter = np.random.exponential(jitter_scale, NUM_SIMULATIONS)
        stochastic_prop_delay = base_prop_delay + network_jitter
        
        transmission_delay = total_wire_bits / (NETWORK_CONFIG["Bandwidth_kbps"] * 1000.0) * 1000.0
        total_handshake_latency = cpu_samples + transmission_delay + stochastic_prop_delay
        simulation_data.append(total_handshake_latency)

    print("\n[KẾT QUẢ THỐNG KÊ MÔ PHỎNG MONTE CARLO]:")
    for idx, proto in enumerate(PROTOCOLS):
        print(f" - {proto:25}: Median = {int(np.median(simulation_data[idx]))} ms")

    fig, ax = plt.subplots(figsize=(11, 6))
    colors = ['#bdc3c7', '#2980b9', '#e74c3c', '#d35400', '#8e44ad', '#27ae60']
    
    bp = ax.boxplot(simulation_data, tick_labels=PROTOCOLS, patch_artist=True, showfliers=False, widths=0.55)
    for element in ['boxes', 'whiskers', 'fliers', 'medians', 'caps']:
        plt.setp(bp[element], color='black', linewidth=1.2)
        
    medians = [np.median(d) for d in simulation_data]
    for patch, color in zip(bp['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.75)
        
    means = [np.mean(d) for d in simulation_data]
    stds = [np.std(d) for d in simulation_data]
    ax.errorbar(range(1, len(PROTOCOLS)+1), means, yerr=stds, fmt='o', color='black', capsize=5, label='Mean ± Std')
    
    ax.set_title(f'Rigorous Monte Carlo End-to-End Latency Model (MTU aware + Exponential Jitter)\nSatellite / IoT Scenario ({NETWORK_CONFIG["Bandwidth_kbps"]} kbps, RTT={NETWORK_CONFIG["RTT_ms"]} ms)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Total Handshake Latency (ms)', fontsize=11, fontweight='bold')
    ax.grid(axis='y', linestyle='--', alpha=0.3)
    
    for i, median in enumerate(medians):
        ax.text(i + 1, median + (max(medians)*0.015), f'{int(median)} ms', ha='center', va='bottom', fontsize=9, fontweight='bold')
        
    ax.set_ylim(0, max([np.percentile(d, 95) for d in simulation_data]) * 1.2)
    ax.legend(loc='upper left')
    
    filename = "chart4_monte_carlo_FN.png"
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[THÀNH CÔNG]: Đã lưu đồ thị xác suất Monte Carlo tại: '{filename}'\n")

# ==============================================================================
# HÀM ĐIỀU KHIỂN CHÍNH
# ==============================================================================
if __name__ == "__main__":
    start_time = time.time()
    run_microbenchmarks()
    plot_tradeoff_chart()    
    plot_network_scenarios()
    plot_break_even_curve()
    run_monte_carlo_simulation()
    print("="*80)
    print(f" HOÀN THÀNH TOÀN BỘ TIẾN TRÌNH THỰC NGHIỆM TRONG: {time.time() - start_time:.2f} GIÂY")
    print("="*80)