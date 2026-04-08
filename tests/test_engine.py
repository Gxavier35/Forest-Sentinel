import pytest
import os
import sys
from unittest.mock import MagicMock

# Ajusta sys.path para encontrar src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from monitor_engine import MonitorEngine
from constants import DetectionStatus

def test_engine_initialization():
    engine = MonitorEngine()
    assert engine._running is False
    assert engine.attack_manager is not None
    assert engine.flow_manager is not None

def test_engine_profile_selection():
    engine = MonitorEngine()
    engine.set_profile("datacenter")
    assert engine._profile == "datacenter"
    
    threshold = engine._ai_thresholds.get("datacenter")
    assert threshold == 0.00

def test_engine_autoblock_toggle():
    engine = MonitorEngine()
    engine.set_autoblock(True)
    assert engine._auto_block_enabled is True
    engine.set_autoblock(False)
    assert engine._auto_block_enabled is False

def test_engine_whitelist_mgmt():
    engine = MonitorEngine()
    ip = "192.168.1.101" # Usa um IP diferente para evitar conflitos
    engine.attack_manager.clear_whitelist()
    engine.add_to_whitelist(ip)
    assert engine.attack_manager.is_whitelisted(ip) is True
    
    engine.remove_from_whitelist(ip)
    assert engine.attack_manager.is_whitelisted(ip) is False

def test_predict_batch_empty():
    engine = MonitorEngine()
    results = engine._predict_batch([])
    assert results == []
