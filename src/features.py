"""
features.py
-----------
Calcula as 38 features de fluxo de rede para o modelo DDoS usando NumPy para alta performance.
"""

import numpy as np
from typing import Dict, Tuple, Optional
from utils import is_private_ip

def _calculate_bulk_vectorized(times: np.ndarray, lengths: np.ndarray, threshold: float = 0.1) -> tuple[float, float, float]:
    """
    Calcula as médias de Bulk usando vetorização NumPy.
    Um Bulk é uma rajada de 4+ pacotes onde cada IAT < threshold.
    """
    if len(times) < 4:
        return 0.0, 0.0, 0.0

    iats = np.diff(times)
    # Identifica onde começam novos blocos (IAT >= threshold)
    break_indices = np.where(iats >= threshold)[0] + 1
    
    # Divide os pacotes em grupos
    burst_times = np.split(times, break_indices)
    burst_lens = np.split(lengths, break_indices)
    
    # Filtra apenas rajadas com 4+ pacotes
    valid_bulks = [(bt, bl) for bt, bl in zip(burst_times, burst_lens) if len(bt) >= 4]
    
    if not valid_bulks:
        return 0.0, 0.0, 0.0

    total_bulk_bytes = sum(np.sum(bl) for _, bl in valid_bulks)
    total_bulk_pkts = sum(len(bl) for _, bl in valid_bulks)
    total_bulk_dur = sum(bt[-1] - bt[0] for bt, _ in valid_bulks)

    num_bulks = len(valid_bulks)
    avg_bytes_bulk = total_bulk_bytes / num_bulks
    avg_pkts_bulk = total_bulk_pkts / num_bulks
    avg_bulk_rate = total_bulk_bytes / max(1e-6, total_bulk_dur)

    return float(avg_bytes_bulk), float(avg_pkts_bulk), float(avg_bulk_rate)


def compute_features(flow_key: tuple, packets: list) -> np.ndarray:
    """
    Calcula as 38 features de um fluxo de rede usando vetorização NumPy.
    """
    if not packets or len(packets) == 0:
        return np.zeros(38, dtype=np.float64)

    # --- Estágio 1: Extração de Dados (Harvesting) ---
    # Convertemos a lista de dicts em arrays NumPy primitivos de uma vez
    data = [(
        p["time"], 
        float(p["length"]), 
        int(p.get("tcp_flags", 0) or 0),
        int(p.get("ip_header_len", 20)),
        int(p.get("tcp_window", 0) or 0),
        p["direction"] == "fwd"
    ) for p in packets]
    
    times, lengths, flags, header_lens, windows, is_fwd = map(np.array, zip(*data))
    is_bwd = ~is_fwd

    total_pkts = len(packets)
    total_bytes = lengths.sum()

    # Revert to original logic: flows with 1 packet have duration 0.0
    flow_duration = float(times[-1] - times[0]) if total_pkts > 1 else 0.0

    flow_bytes_s = total_bytes / flow_duration if flow_duration > 0 else 0.0
    flow_pkts_s = total_pkts / flow_duration if flow_duration > 0 else 0.0
    
    min_pkt_length = float(lengths.min())
    pkt_len_var = float(np.var(lengths)) if total_pkts > 1 else 0.0

    # --- Estágio 3: Separação por Direção (Forward / Backward) ---
    fwd_times = times[is_fwd]
    bwd_times = times[is_bwd]
    fwd_lengths = lengths[is_fwd]
    bwd_lengths = lengths[is_bwd]

    num_fwd = len(fwd_times)
    num_bwd = len(bwd_times)

    fwd_pkt_max = float(fwd_lengths.max()) if num_fwd > 0 else 0.0
    fwd_pkt_min = float(fwd_lengths.min()) if num_fwd > 0 else 0.0
    bwd_pkt_min = float(bwd_lengths.min()) if num_bwd > 0 else 0.0

    fwd_iat = np.diff(fwd_times) if num_fwd > 1 else np.array([0.0])
    bwd_iat = np.diff(bwd_times) if num_bwd > 1 else np.array([0.0])
    fwd_iat_min = float(fwd_iat.min()) if len(fwd_iat) > 0 else 0.0
    bwd_iat_min = float(bwd_iat.min()) if len(bwd_iat) > 0 else 0.0

    fwd_bytes = float(fwd_lengths.sum())
    bwd_bytes = float(bwd_lengths.sum())
    down_up_ratio = bwd_bytes / fwd_bytes if fwd_bytes > 0 else 0.0

    bwd_duration = float(bwd_times[-1] - bwd_times[0]) if num_bwd > 1 else 0.0
    bwd_pkts_s = num_bwd / bwd_duration if bwd_duration > 0 else 0.0

    # --- Estágio 4: Estatísticas de Flags TCP (Vetorizadas) ---
    # bitwise AND em todo o array de flags
    fin_count = int((flags & 0x01).astype(bool).sum())
    syn_count = int((flags & 0x02).astype(bool).sum())
    rst_count = int((flags & 0x04).astype(bool).sum())
    psh_count = int((flags & 0x08).astype(bool).sum())
    ack_count = int((flags & 0x10).astype(bool).sum())
    urg_count = int((flags & 0x20).astype(bool).sum())
    ece_count = int((flags & 0x40).astype(bool).sum())
    cwr_count = int((flags & 0x80).astype(bool).sum())

    bwd_psh = int((flags[is_bwd] & 0x08).astype(bool).sum())
    bwd_urg = int((flags[is_bwd] & 0x20).astype(bool).sum())
    fwd_urg = int((flags[is_fwd] & 0x20).astype(bool).sum())

    # --- Estágio 5: Header e Windows ---
    fwd_header_len = float(header_lens[is_fwd].sum())
    bwd_header_len = float(header_lens[is_bwd].sum())

    # Janela inicial (exatamente o primeiro pacote de cada direção, como no treinamento)
    fwd_wins = windows[is_fwd]
    bwd_wins = windows[is_bwd]
    init_win_fwd = int(fwd_wins[0]) if num_fwd > 0 else 0
    init_win_bwd = int(bwd_wins[0]) if num_bwd > 0 else 0

    # --- Estágio 6: Bulk, Active e Idle ---
    fwd_avg_bytes_bulk, fwd_avg_pkts_bulk, fwd_avg_bulk_rate = _calculate_bulk_vectorized(fwd_times, fwd_lengths)
    bwd_avg_bytes_bulk, bwd_avg_pkts_bulk, bwd_avg_bulk_rate = _calculate_bulk_vectorized(bwd_times, bwd_lengths)

    # Active/Idle logic (Vetorizada)
    idle_threshold = 1.0
    iats = np.diff(times)
    idle_indices = np.where(iats > idle_threshold)[0]
    
    # Active duration = tempo entre gaps de idle
    starts = np.concatenate(([times[0]], times[idle_indices + 1]))
    ends = np.concatenate((times[idle_indices], [times[-1]]))
    active_times = ends - starts
    
    # Idle duration = o próprio gap
    idle_times = iats[idle_indices] if len(idle_indices) > 0 else np.array([0.0])

    active_std = float(np.std(active_times)) if len(active_times) > 1 else 0.0
    active_max = float(np.max(active_times))
    idle_std = float(np.std(idle_times)) if len(idle_times) > 1 else 0.0

    # --- Estágio 7: Inbound ---
    src_ip, dst_ip, *_ = flow_key
    inbound = 1.0 if (not is_private_ip(src_ip) and is_private_ip(dst_ip)) else 0.0

    # --- Assemblagem Final ---
    features = np.array([
        flow_duration, fwd_pkt_max, fwd_pkt_min, bwd_pkt_min, flow_bytes_s, flow_pkts_s,
        fwd_iat_min, bwd_iat_min, float(bwd_psh), float(fwd_urg), float(bwd_urg),
        bwd_header_len, bwd_pkts_s, min_pkt_length, pkt_len_var, float(fin_count),
        float(syn_count), float(rst_count), float(psh_count), float(ack_count),
        float(urg_count), float(cwr_count), float(ece_count), down_up_ratio,
        fwd_header_len, fwd_avg_bytes_bulk, fwd_avg_pkts_bulk, fwd_avg_bulk_rate,
        bwd_avg_bytes_bulk, bwd_avg_pkts_bulk, bwd_avg_bulk_rate, fwd_bytes,
        float(init_win_fwd), float(init_win_bwd), active_std, active_max,
        idle_std, inbound
    ], dtype=np.float64)

    # Clipping e Proteção contra NaN
    features = np.nan_to_num(features, nan=0.0)
    features = np.clip(features, -1e5, 1e5)
    return features
