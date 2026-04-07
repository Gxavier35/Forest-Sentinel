import pytest
import numpy as np
from features import _calculate_bulk, compute_features

def test_calculate_bulk():
    # Testa os processamentos estatisticos para tamanhos uniformes e anômalos
    # _calculate_bulk processa uma lista de pacotes {time, length}
    pkts = [
        {"length": 50, "time": 10.0},
        {"length": 150, "time": 10.05},
        {"length": 50, "time": 10.1},
        {"length": 50, "time": 10.15}
    ]
    
    # Bulk exige no minimo 4 pacotes, testaremos se gera metricas base
    bytes_bulk, pkts_bulk, rate = _calculate_bulk(pkts)
    
    assert bytes_bulk == 300.0
    assert pkts_bulk == 4.0
    assert rate > 0

def test_compute_features_no_nan():
    # Garante validacao defensiva impedindo corrupcao numerica em features
    rec = type("FlowRecord", (), {})()
    rec.start_time = 1600000000
    rec.last_seen = 1600000005
    
    packets = [
        {"direction": "fwd", "length": 64,  "time": 1.0, "tcp_flags": 2, "tcp_window": 8192, "ip_header_len": 20},
        {"direction": "bwd", "length": 128, "time": 1.1, "tcp_flags": 18, "tcp_window": 8192, "ip_header_len": 20},
        {"direction": "fwd", "length": 512, "time": 1.2, "tcp_flags": 24, "tcp_window": 8192, "ip_header_len": 20},
        {"direction": "bwd", "length": 64,  "time": 1.3, "tcp_flags": 16, "tcp_window": 8192, "ip_header_len": 20},
        {"direction": "fwd", "length": 512, "time": 1.4, "tcp_flags": 24, "tcp_window": 8192, "ip_header_len": 20}
    ]
    
    flow_key = ("192.168.1.1", "8.8.8.8", 12345, 443, 6) # tcp
    feat_vector = compute_features(flow_key, packets)
    
    # Vetor das 38 colunas originais do paper final da engine de IA
    assert len(feat_vector) == 38
    
    # Nao pode haver nulls, Nans ou Infinities para a IA nao crashar as weights
    assert not np.isnan(feat_vector).any()
    assert not np.isinf(feat_vector).any()
