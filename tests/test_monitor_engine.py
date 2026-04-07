import pytest
import time
from unittest.mock import MagicMock
from attack_manager import AttackStateManager
from flow_manager import FlowManager

def test_flow_manager_cleanup():
    fm = FlowManager()
    fm._flows[("1.1.1.1", "2.2.2.2", 80, 443, 6)] = MagicMock(last_seen=time.time())
    fm._flows[("3.3.3.3", "4.4.4.4", 80, 443, 6)] = MagicMock(last_seen=time.time() - 20)  # > FLOW_TIMEOUT (10)
    
    removed = fm.cleanup_memory()
    assert ("3.3.3.3", "4.4.4.4", 80, 443, 6) in removed
    assert ("1.1.1.1", "2.2.2.2", 80, 443, 6) not in removed
    assert len(fm._flows) == 1

def test_attack_manager_cleanup_blocked():
    am = AttackStateManager()
    am.firewall = MagicMock()
    now = time.time()
    
    # Recém bloqueado
    am._blocked_status["1.1.1.1"] = {"time": "12:00:00", "block_time": now, "pps": 500}
    # Bloqueado há muito tempo (mais de 2 dias / 172800)
    am._blocked_status["8.8.8.8"] = {"time": "00:00:00", "block_time": now - 180000, "pps": 9000}
    
    am.cleanup_memory()
    
    # 1.1.1.1 deve permanecer. 8.8.8.8 deve ter saído.
    assert "1.1.1.1" in am._blocked_status
    assert "8.8.8.8" not in am._blocked_status

def test_whitelist_parsing():
    am = AttackStateManager()
    for ip in ["192.168.1.100", "10.0.0.0/24", "invalid_ip_format"]:
        am.add_to_whitelist(ip)
    
    assert am.is_whitelisted("192.168.1.100") is True
    assert am.is_whitelisted("10.0.0.50") is True
    assert am.is_whitelisted("10.0.1.50") is False
    assert am.is_whitelisted("8.8.8.8") is False

def test_attack_manager_tracking_purge():
    am = AttackStateManager()
    now = time.time()
    
    # Flow tracking persiste na memoria
    am._attack_persist["1.1.1.1"] = now
    am._attack_persist["8.8.8.8"] = now - 100 
    
    # Fornece apenas o 1.1.1.1 ativo. O 8.8.8.8 está stale
    stale = am.get_stale_from_tracking(["1.1.1.1"])
    
    assert "8.8.8.8" in stale
    assert "1.1.1.1" not in stale
    assert "8.8.8.8" not in am._attack_persist
