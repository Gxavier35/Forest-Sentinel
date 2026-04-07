import pytest
import numpy as np
from features import compute_features

def test_compute_features_basic():
    # Teste básico com uma lista de pacotes simulada
    pkts = [
        {"time": 0.0, "length": 60, "tcp_flags": 2, "tcp_window": 1024, "direction": "fwd"},
        {"time": 0.1, "length": 1500, "tcp_flags": 2, "tcp_window": 1024, "direction": "fwd"},
        {"time": 0.2, "length": 60, "tcp_flags": 2, "tcp_window": 1024, "direction": "bwd"},
        {"time": 0.3, "length": 60, "tcp_flags": 2, "tcp_window": 1024, "direction": "fwd"},
        {"time": 0.4, "length": 60, "tcp_flags": 2, "tcp_window": 1024, "direction": "bwd"},
    ]
    key = ("1.1.1.1", "2.2.2.2", 1234, 80, 6) # TCP
    
    features = compute_features(key, pkts)
    
    assert isinstance(features, np.ndarray)
    assert features.shape == (38,) # O modelo espera exatamente 38 features
    # Feature 0: duration
    assert features[0] > 0.3 # 0.4 - 0.0
    # Feature 5: flow_packets_per_sec (index 5)
    assert features[5] > 0

def test_compute_features_udp():
    pkts = [
        {"time": 0.0, "length": 100, "tcp_flags": None, "tcp_window": None, "direction": "fwd"},
        {"time": 0.1, "length": 100, "tcp_flags": None, "tcp_window": None, "direction": "bwd"},
        {"time": 0.2, "length": 100, "tcp_flags": None, "tcp_window": None, "direction": "fwd"},
        {"time": 0.3, "length": 100, "tcp_flags": None, "tcp_window": None, "direction": "bwd"},
        {"time": 0.4, "length": 100, "tcp_flags": None, "tcp_window": None, "direction": "fwd"},
    ]
    key = ("1.1.1.1", "2.2.2.2", 1234, 53, 17) # UDP
    
    features = compute_features(key, pkts)
    assert features.shape == (38,)
    # TCP-specific features should be 0 for UDP
    # fwd_psh_flags is at index 14
    assert features[14] == 0
