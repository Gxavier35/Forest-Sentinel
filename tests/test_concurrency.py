import os
import sys
import time
import threading
import numpy as np
import pytest

# Adjust sys.path to find src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from monitor_engine import MonitorEngine
from constants import DetectionStatus

def test_predict_batch_concurrency():
    """
    Testa se múltiplas threads chamando _predict_batch recebem as respostas corretas.
    """
    engine = MonitorEngine()
    
    # Carrega o modelo (necessário para o worker funcionar)
    if not engine.load_model():
        pytest.skip("Modelos não encontrados, pulando teste de concorrência real.")
    
    engine._start_ai_process()
    
    # Lista para armazenar resultados das threads
    thread_results = {}
    errors = []

    def worker_thread(thread_id, num_samples):
        try:
            # Cria dados fictícios (38 features)
            feats = [np.zeros(38) for _ in range(num_samples)]
            
            # Chama a predição
            result = engine._predict_batch(feats)
            
            # Verifica se o tamanho do resultado bate com o solicitado
            if len(result) != num_samples:
                errors.append(f"Thread {thread_id}: Tamanho incorreto {len(result)} != {num_samples}")
            
            thread_results[thread_id] = result
        except Exception as e:
            errors.append(f"Thread {thread_id}: Erro {e}")

    # Dispara múltiplas threads com cargas diferentes
    threads = []
    configs = [
        (1, 5),   # Thread 1 pede 5 predições
        (2, 10),  # Thread 2 pede 10 predições
        (3, 3),   # Thread 3 pede 3 predições
        (4, 7),   # Thread 4 pede 7 predições
    ]

    for tid, count in configs:
        t = threading.Thread(target=worker_thread, args=(tid, count))
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=10)

    # Cleanup
    engine.stop()

    # Validações
    assert not errors, f"Erros detectados: {errors}"
    assert len(thread_results) == len(configs), "Nem todas as threads completaram."
    
    for tid, count in configs:
        assert len(thread_results[tid]) == count, f"Thread {tid} recebeu quantidade errada de respostas."

if __name__ == "__main__":
    test_predict_batch_concurrency()
