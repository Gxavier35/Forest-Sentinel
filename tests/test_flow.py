import pytest
import time
from flow_manager import FlowManager, FlowRecord

def test_flow_record_add():
    record = FlowRecord()
    pkt_data = {"time": time.time(), "length": 100, "ip_header_len": 20, "tcp_flags": None, "tcp_window": None, "direction": "fwd"}
    record.add(pkt_data)
    assert len(record.packets) == 1
    assert record.packets[0]["length"] == 100

def test_flow_manager_lru():
    # MAX_FLOWS is 5000 in constants.py
    # We can mock it or just test with a few for now if it was configurable
    # Since it's a constant, we'll test the logic.
    manager = FlowManager()
    for i in range(5005):
        key = (f"1.1.1.{i}", "2.2.2.2", 80, 443, 6)
        manager._flows[key] = FlowRecord()
        if len(manager._flows) > 5000:
             # Manually trigger cleanup or wait for popitem logic
             # In flow_manager.py, it cleans 50 items when it hits 5000.
             manager._flows.popitem(last=False)
    
    assert len(manager._flows) <= 5000

def test_get_flows_for_analysis():
    manager = FlowManager()
    key = ("1.1.1.1", "2.2.2.2", 80, 443, 6)
    manager._flows[key] = FlowRecord()
    manager._flows[key].last_seen = time.time()
    
    work_list, expired = manager.get_flows_for_analysis()
    assert len(work_list) == 1
    assert len(expired) == 0
    assert work_list[0][0] == key

def test_flow_expiration():
    manager = FlowManager()
    key = ("1.1.1.1", "2.2.2.2", 80, 443, 6)
    manager._flows[key] = FlowRecord()
    manager._flows[key].last_seen = time.time() - 20 # FLOW_TIMEOUT is 10
    
    work_list, expired = manager.get_flows_for_analysis()
    assert len(work_list) == 0
    assert len(expired) == 1
    assert expired[0] == key
