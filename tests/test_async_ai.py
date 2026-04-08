import os
import sys
import time
import threading
import numpy as np
import pytest
from unittest.mock import MagicMock

# Adjust sys.path to find src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from monitor_engine import MonitorEngine
from constants import DetectionStatus

def test_async_ai_heartbeat():
    """
    Valida que o loop de análise não trava quando a IA demora para responder.
    """
    engine = MonitorEngine()
    engine.MAX_AI_IN_FLIGHT = 1 # Facilita o teste de limite
    
    # Mock do flow_manager para simular tráfego
    engine.flow_manager = MagicMock()
    engine.flow_manager.get_and_reset_pkt_count.return_value = (100, time.time() - 1)
    
    # Simula 1 fluxo para analisar
    mock_flow_key = ("1.2.3.4", "5.6.7.8", 80, 443, 6)
    mock_rec = MagicMock()
    mock_rec.last_result = None
    engine.flow_manager.get_flows_for_analysis.return_value = ([(mock_flow_key, mock_rec, [{"time": time.time()}], 0, 0, 0, True)], [])
    engine.flow_manager.batch_extract_features.return_value = ([mock_flow_key], [np.zeros(38)])
    
    # Mock do queue da IA para simular delay
    engine._in_q = MagicMock()
    engine._out_q = MagicMock()
    engine._ai_proc = MagicMock()
    engine._ai_proc.is_alive.return_value = True
    engine._start_ai_process = MagicMock()  # Evita erro de pickling no Windows
    
    # Inicia o motor (sem sniffer real)
    engine._running = True
    
    # Medir tempo de execução de um pipeline que "esperaria" pela IA
    start_time = time.time()
    engine._evaluate_threat_pipeline()
    end_time = time.time()
    
    # O pipeline DEVE ser quase instantâneo (não deve esperar a IA)
    elapsed = end_time - start_time
    assert elapsed < 0.1, f"O pipeline bloqueou por {elapsed}s"
    
    # Verifica se a task foi para o mapa de pendentes
    assert len(engine._ai_pending_tasks) == 1
    
    # Simula a chegada da resposta tardia
    req_id = list(engine._ai_pending_tasks.keys())[0]
    engine._ai_results[req_id] = ("OK", [(DetectionStatus.ATTACK, 0.9, True)])
    
    # Próximo ciclo deve processar o resultado
    engine._evaluate_threat_pipeline()
    
    # Verifica se o resultado foi aplicado e a task removida
    assert engine.flow_manager.apply_batch_results.called
    assert len(engine._ai_pending_tasks) == 0
    
    engine._running = False

if __name__ == "__main__":
    test_async_ai_heartbeat()
