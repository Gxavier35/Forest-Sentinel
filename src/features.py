"""
features.py
-----------
Calcula as 38 features de fluxo de rede para o modelo DDoS.
"""

import numpy as np
from utils import is_private_ip

def _tcp_flags(pkt_flags):
    """Retorna dict com flags TCP."""
    flags = {
        "FIN": 0,
        "SYN": 0,
        "RST": 0,
        "PSH": 0,
        "ACK": 0,
        "URG": 0,
        "ECE": 0,
        "CWR": 0,
    }
    if pkt_flags is None:
        return flags
    f = int(pkt_flags)
    flags["FIN"] = 1 if f & 0x01 else 0
    flags["SYN"] = 1 if f & 0x02 else 0
    flags["RST"] = 1 if f & 0x04 else 0
    flags["PSH"] = 1 if f & 0x08 else 0
    flags["ACK"] = 1 if f & 0x10 else 0
    flags["URG"] = 1 if f & 0x20 else 0
    flags["ECE"] = 1 if f & 0x40 else 0
    flags["CWR"] = 1 if f & 0x80 else 0
    return flags


def _calculate_bulk(packets, threshold=0.1):
    """
    Calcula as médias de Bulk para uma direção seguindo o padrão CICFlowMeter.
    Um Bulk é definido por uma rajada de 4+ pacotes onde cada intervalo < threshold.
    """
    if len(packets) < 4:
        return 0.0, 0.0, 0.0

    bulks = []
    current_bulk = [packets[0]]
    for i in range(1, len(packets)):
        iat = packets[i]["time"] - packets[i-1]["time"]
        if iat < threshold:
            current_bulk.append(packets[i])
        else:
            if len(current_bulk) >= 4:
                bulks.append(current_bulk)
            current_bulk = [packets[i]]
    
    if len(current_bulk) >= 4:
        bulks.append(current_bulk)

    if not bulks:
        return 0.0, 0.0, 0.0

    total_bulk_bytes = sum(sum(p["length"] for p in b) for b in bulks)
    total_bulk_pkts = sum(len(b) for b in bulks)
    total_bulk_dur = sum(b[-1]["time"] - b[0]["time"] for b in bulks)

    avg_bytes_bulk = total_bulk_bytes / len(bulks)
    avg_pkts_bulk = total_bulk_pkts / len(bulks)
    avg_bulk_rate = total_bulk_bytes / max(1e-6, total_bulk_dur)

    return float(avg_bytes_bulk), float(avg_pkts_bulk), float(avg_bulk_rate)


def compute_features(flow_key, packets):
    """
    Calcula as 38 features de um fluxo de rede.

    Parameters
    ----------
    flow_key : tuple
        (src_ip, dst_ip, src_port, dst_port, proto)
    packets : list of dict
        Cada item: {
            'time': float,
            'length': int,
            'ip_header_len': int,
            'tcp_flags': int|None,
            'tcp_window': int|None,
            'direction': 'fwd'|'bwd'
        }

    Returns
    -------
    np.ndarray shape (38,)
        Sempre retorna um array numpy quantificado (zeros como fallback predeterminado para proteção).
    """
    packets = list(packets)

    *_, proto = flow_key  # apenas proto e usado no calculo

    times = np.array([p["time"] for p in packets])
    lengths = np.array([p["length"] for p in packets])

    fwd = [p for p in packets if p["direction"] == "fwd"]
    bwd = [p for p in packets if p["direction"] == "bwd"]

    fwd_lengths = (
        np.array([p["length"] for p in fwd], dtype=np.float64)
        if fwd
        else np.array([], dtype=np.float64)
    )
    bwd_lengths = (
        np.array([p["length"] for p in bwd], dtype=np.float64)
        if bwd
        else np.array([], dtype=np.float64)
    )

    fwd_times = (
        np.array([p["time"] for p in fwd], dtype=np.float64)
        if fwd
        else np.array([], dtype=np.float64)
    )
    bwd_times = (
        np.array([p["time"] for p in bwd], dtype=np.float64)
        if bwd
        else np.array([], dtype=np.float64)
    )

    flow_duration = float(times[-1] - times[0])
    if flow_duration <= 0:
        flow_duration = 1e-6

    total_bytes = int(lengths.sum())
    total_pkts = len(packets)

    flow_bytes_s = total_bytes / flow_duration
    flow_pkts_s = total_pkts / flow_duration

    fwd_pkt_max = float(fwd_lengths.max()) if len(fwd) > 0 else 0.0
    fwd_pkt_min = float(fwd_lengths.min()) if len(fwd) > 0 else 0.0
    bwd_pkt_min = float(bwd_lengths.min()) if len(bwd) > 0 else 0.0
    min_pkt_length = float(lengths.min())

    pkt_len_var = float(np.var(lengths)) if len(lengths) > 1 else 0.0

    fwd_iat = np.diff(fwd_times) if len(fwd) > 1 else np.array([0.0])
    bwd_iat = np.diff(bwd_times) if len(bwd) > 1 else np.array([0.0])
    flow_iat = np.diff(times) if len(packets) > 1 else np.array([0.0])

    fwd_iat_total = float(fwd_times[-1] - fwd_times[0]) if len(fwd) > 1 else 0.0
    bwd_iat_total = float(bwd_times[-1] - bwd_times[0]) if len(bwd) > 1 else 0.0
    
    flow_iat_mean = float(np.mean(flow_iat))
    flow_iat_std = float(np.std(flow_iat))
    
    fwd_iat_min = float(fwd_iat.min()) if len(fwd_iat) > 0 else 0.0
    bwd_iat_min = float(bwd_iat.min()) if len(bwd_iat) > 0 else 0.0

    fin_count = syn_count = rst_count = psh_count = 0
    ack_count = urg_count = ece_count = cwr_count = 0
    bwd_psh = bwd_urg = 0
    fwd_urg = 0

    bwd_header_len = 0
    fwd_header_len = 0
    init_win_fwd = 0
    init_win_bwd = 0
    got_fwd_win = False
    got_bwd_win = False

    for p in packets:
        fl = _tcp_flags(p.get("tcp_flags"))
        fin_count += fl["FIN"]
        syn_count += fl["SYN"]
        rst_count += fl["RST"]
        psh_count += fl["PSH"]
        ack_count += fl["ACK"]
        urg_count += fl["URG"]
        ece_count += fl["ECE"]
        cwr_count += fl["CWR"]

        if p["direction"] == "bwd":
            bwd_psh += fl["PSH"]
            bwd_urg += fl["URG"]
            bwd_header_len += p.get("ip_header_len", 20)
            if not got_bwd_win and p.get("tcp_window") is not None:
                init_win_bwd = int(p["tcp_window"])
                got_bwd_win = True
        else:
            fwd_urg += fl["URG"]
            fwd_header_len += p.get("ip_header_len", 20)
            if not got_fwd_win and p.get("tcp_window") is not None:
                init_win_fwd = int(p["tcp_window"])
                got_fwd_win = True

    fwd_bytes = int(fwd_lengths.sum())
    bwd_bytes = int(bwd_lengths.sum())
    down_up_ratio = bwd_bytes / fwd_bytes if fwd_bytes > 0 else 0.0

    bwd_duration = float(bwd_times[-1] - bwd_times[0]) if len(bwd) > 1 else 0.0
    if bwd_duration < 0:
        bwd_duration = 0.0
    bwd_pkts_s = len(bwd) / bwd_duration if bwd_duration > 0 else 0.0

    fwd_avg_bytes_bulk, fwd_avg_pkts_bulk, fwd_avg_bulk_rate = _calculate_bulk(fwd)
    bwd_avg_bytes_bulk, bwd_avg_pkts_bulk, bwd_avg_bulk_rate = _calculate_bulk(bwd)

    subflow_fwd_bytes = fwd_bytes

    active_times = []  # durações de janelas ativas
    idle_times = []  # tempos entre janelas

    idle_threshold = 1.0  # Padrão fixo do dataset CICFlowMeter

    current_window_start = packets[0]["time"]
    last_pkt_time = packets[0]["time"]

    for p in packets[1:]:
        iat = p["time"] - last_pkt_time
        if iat > idle_threshold:
            active_times.append(last_pkt_time - current_window_start)
            idle_times.append(iat)
            current_window_start = p["time"]
        last_pkt_time = p["time"]
    active_times.append(last_pkt_time - current_window_start)

    if not active_times:
        active_times = [0.0]
    if not idle_times:
        idle_times = [0.0]

    active_std = float(np.std(active_times))
    active_max = float(np.max(active_times))
    idle_std = float(np.std(idle_times))

    # Feature 38: Inbound. Calculado baseando-se no destino do fluxo
    # se o destino eh interno e origem externa, inbound=1.0
    src_ip, dst_ip, *_ = flow_key
    src_local = is_private_ip(src_ip)
    dst_local = is_private_ip(dst_ip)
    
    inbound = 1.0 if (not src_local and dst_local) else 0.0

    features = np.array(
        [
            flow_duration,  # 1
            fwd_pkt_max,  # 2
            fwd_pkt_min,  # 3
            bwd_pkt_min,  # 4
            flow_bytes_s,  # 5
            flow_pkts_s,  # 6
            fwd_iat_min,   # 7
            bwd_iat_min,   # 8
            float(bwd_psh),# 9
            float(fwd_urg),# 10
            float(bwd_urg),# 11
            float(bwd_header_len),  # 12
            bwd_pkts_s,  # 13
            min_pkt_length,  # 14
            pkt_len_var,  # 15
            float(fin_count),  # 16
            float(syn_count),  # 17
            float(rst_count),  # 18
            float(psh_count),  # 19
            float(ack_count),  # 20
            float(urg_count),  # 21
            float(
                cwr_count
            ),  # 22 → "CWE Flag Count" (nome do treinamento; bit físico = CWR)
            float(ece_count),  # 23
            down_up_ratio,  # 24
            float(fwd_header_len),  # 25
            fwd_avg_bytes_bulk,  # 26
            fwd_avg_pkts_bulk,  # 27
            fwd_avg_bulk_rate,  # 28
            bwd_avg_bytes_bulk,  # 29
            bwd_avg_pkts_bulk,  # 30
            bwd_avg_bulk_rate,  # 31
            float(subflow_fwd_bytes),  # 32
            float(init_win_fwd),  # 33
            float(init_win_bwd),  # 34
            active_std,  # 35
            active_max,  # 36
            idle_std,  # 37
            float(inbound),  # 38
        ],
        dtype=np.float64,
    )

    # Clipping e Normalização final (Isolation Forest é sensível a escala massiva)
    features = np.nan_to_num(features, nan=0.0, posinf=1e6, neginf=-1e6)
    return features
