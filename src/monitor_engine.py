"""
monitor_engine.py
------------------
Motor de captura de pacotes e detecção de DDoS.
Atua como orquestrador entre os Módulos de Fluxo, Processamento IA e Regras de Bloqueio.
Gera eventos de UI via Qt Signals.
"""

import os
import sys
import time
import joblib
import threading
import logging
import traceback
import multiprocessing as mp
from datetime import datetime

import queue
from PyQt6.QtCore import QObject, pyqtSignal, QTimer

import numpy as np

try:
    from scapy.all import AsyncSniffer

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from utils import get_root_dir
from firewall import get_firewall_manager

# --- Gerenciadores de Estado --- #
from constants import DetectionStatus
from flow_manager import FlowManager
from attack_manager import AttackStateManager

_ROOT = get_root_dir()

MODEL_PATH = os.path.join(_ROOT, "models", "ddos_detection.pkl")
SCALER_PATH = os.path.join(_ROOT, "models", "scaler.pkl")


def _ai_inference_worker(in_queue, out_queue, model_path, scaler_path):
    """Processo isolado para inferência da Inteligência Artificial (Evita gargalos com o GIL temporal)."""
    import warnings

    warnings.filterwarnings("ignore", category=UserWarning)

    try:
        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
    except Exception as e:
        out_queue.put(("ERROR", str(e)))
        return

    while True:
        try:
            item = in_queue.get()
            if item == "STOP":
                break

            req_id, feats_combined, threshold = item
            X_scaled = scaler.transform(feats_combined)
            scores = model.decision_function(X_scaled)

            batch_results = []
            for s in scores:
                score_val = float(s)
                is_attack = score_val < threshold
                confidence = max(0.0, min(1.0, abs(score_val)))
                label = DetectionStatus.ATTACK if is_attack else DetectionStatus.NORMAL
                batch_results.append((label, confidence, is_attack))

            out_queue.put((req_id, "OK", batch_results))
        except Exception as e:
            err_req_id = item[0] if isinstance(item, tuple) and len(item) > 0 else 0
            out_queue.put((err_req_id, "ERROR", str(e)))


class MonitorEngine(QObject):
    """
    Orquestrador. Instancia FlowManager e AttackStateManager.
    """

    error_occurred = pyqtSignal(str)
    status_changed = pyqtSignal(str)
    pps_updated = pyqtSignal(float)

    # Eventos de Ataque e Firewall
    block_requested = pyqtSignal(str, float)
    ip_blocked = pyqtSignal(str, float, str)
    ip_unblocked = pyqtSignal(str)
    state_sync = pyqtSignal(
        dict
    )  # Para atualizar tabela de bloqueados em tempo real na aba Firewall

    # Sinais Visuais da UI
    whitelist_changed = pyqtSignal(list)
    attack_normalized = pyqtSignal(dict)
    attack_started = pyqtSignal(str, str)  # IP, Label
    flow_batch_ready = pyqtSignal(
        list, int, int
    )  # (top_50_results, total_active, total_attacks)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.model = None
        self.scaler = None
        self.sniffer = None
        self._running = False
        self._analyze_thread = None
        self._sniffer_thread = None

        self._last_pps_chk = time.time()
        self._baseline_pps = 0.0
        self._profile = "home"
        self._ai_thresholds = {
            "home": -0.30,
            "pme": -0.15,
            "datacenter": 0.00,
        }
        self._zero_traffic_cycles = 0
        self._warned_no_traffic = False
        self._auto_block_enabled = False
        self._manual_autoblock: bool | None = None
        self._last_cleanup_time = 0.0
        self._last_ai_restart = 0.0

        self._in_q = mp.Queue()
        self._out_q = mp.Queue()
        self._ai_proc = None

        self.firewall = get_firewall_manager()
        self.logger = logging.getLogger("Engine")

        # Injeção de dependência dos Managers
        self.flow_manager = FlowManager()
        self.attack_manager = AttackStateManager()

        # Fila de firewall para evitar thread explosion
        self._block_queue = queue.Queue()
        self._firewall_thread = threading.Thread(
            target=self._firewall_worker, daemon=True
        )
        self._firewall_thread.start()

    def is_running(self) -> bool:
        return self._running

    # --- Rotinas da Whitelist ---
    def add_to_whitelist(self, val: str) -> bool:
        ret = self.attack_manager.add_to_whitelist(val)
        if ret:
            self.whitelist_changed.emit(self.attack_manager.get_whitelist_items())
        return ret

    def clear_whitelist(self):
        self.attack_manager.clear_whitelist()
        self.whitelist_changed.emit([])

    def remove_from_whitelist(self, val: str) -> bool:
        ret = self.attack_manager.remove_from_whitelist(val)
        if ret:
            self.whitelist_changed.emit(self.attack_manager.get_whitelist_items())
        return ret

    def get_whitelist_items(self) -> list[str]:
        return self.attack_manager.get_whitelist_items()

    def set_ai_threshold(self, profile_id: str, value: float):
        if profile_id in self._ai_thresholds:
            self._ai_thresholds[profile_id] = float(value)
            self.logger.info(f"Threshold IA '{profile_id}': {value:.3f}")

    def set_profile(self, profile: str):
        self._profile = profile
        if self._manual_autoblock is None:
            self._auto_block_enabled = profile in ("pme", "datacenter")
        self.logger.info(f"Perfil: {profile} | Auto-block: {self._auto_block_enabled}")

    def set_autoblock(self, enabled: bool):
        self._auto_block_enabled = enabled
        self._manual_autoblock = enabled
        self.logger.info(f"Auto-block {'ativado' if enabled else 'desativado'}.")

    def get_blocked_ips(self) -> dict:
        return self.attack_manager.get_blocked_snapshot()

    def get_config_snapshot(self) -> dict:
        return {
            "profile": self._profile,
            "autoblock": self._auto_block_enabled,
            "ai_thresholds": dict(self._ai_thresholds),
        }

    # --- Rotinas do Firewall ---

    def _firewall_worker(self):
        """Thread dedicada para processar bloqueios de forma serializada."""
        while True:
            try:
                task = self._block_queue.get()
                if task == "STOP":
                    break
                ip, pps = task
                self.block_ip(ip, pps)
                self._block_queue.task_done()
            except Exception as e:
                self.logger.error(f"Erro no firewall worker: {e}")

    def block_ip(self, src_ip: str, pkts_per_sec: float) -> bool:
        if self.attack_manager.is_block_pending_or_active(src_ip):
            return False

        self.attack_manager.set_blocking_placeholder(src_ip, pkts_per_sec)
        self.state_sync.emit(self.attack_manager.get_blocked_snapshot())

        if self.firewall.block(src_ip):
            ts = self.attack_manager.confirm_block(src_ip, pkts_per_sec)
            self.ip_blocked.emit(src_ip, pkts_per_sec, ts)
            self.state_sync.emit(self.attack_manager.get_blocked_snapshot())
            return True
        else:
            self.attack_manager.remove_blocked_status(src_ip)
            self.state_sync.emit(self.attack_manager.get_blocked_snapshot())
            return False

    def unblock_ip(self, src_ip: str):
        self.firewall.unblock(src_ip)
        self.attack_manager.remove_blocked_status(src_ip)
        self.logger.info(f"IP desbloqueado: {src_ip}")
        self.ip_unblocked.emit(src_ip)
        self.state_sync.emit(self.attack_manager.get_blocked_snapshot())

    def unblock_all(self):
        self.firewall.unblock_all()
        curr_bl = self.attack_manager.get_blocked_snapshot()
        for ip in curr_bl.keys():
            self.ip_unblocked.emit(ip)

        self.attack_manager.clear_blocked_states()
        self.logger.info("Todos os IPs foram desbloqueados e estado limpo.")
        self.state_sync.emit({})

    # --- Ciclo de Vida do Motor de IA ---

    def load_model(self) -> bool:
        ok = True
        try:
            self.model = joblib.load(MODEL_PATH)
            self.logger.info(f"Modelo carregado: {type(self.model).__name__}")
            self.status_changed.emit(
                f"✅ Modelo carregado: {type(self.model).__name__}"
            )
        except Exception as e:
            self.logger.error(f"Erro ao carregar modelo: {e}")
            self.error_occurred.emit(f"Erro ao carregar modelo: {e}")
            ok = False

        try:
            self.scaler = joblib.load(SCALER_PATH)
            self.logger.info("Scaler carregado.")
            self.status_changed.emit("✅ Scaler carregado.")
        except Exception as e:
            self.logger.error(f"Erro ao carregar scaler: {e}")
            self.error_occurred.emit(f"Erro ao carregar scaler: {e}")
            ok = False

        return ok

    def _start_ai_process(self):
        # Reinicia se o processo não existir ou não estiver vivo
        if self._ai_proc and self._ai_proc.is_alive():
            return

        self.logger.info("📦 Motor de IA: Iniciando processo worker...")
        self._ai_proc = mp.Process(
            target=_ai_inference_worker,
            args=(self._in_q, self._out_q, MODEL_PATH, SCALER_PATH),
            daemon=True,
        )
        self._ai_proc.start()
        self._last_ai_restart = time.time()

    # --- Ciclo de Vida do Orquestrador Principal ---

    def start(self, iface=None) -> bool:
        if self._running:
            return False

        if not SCAPY_AVAILABLE:
            self.error_occurred.emit(
                "Scapy não encontrado. Instale com: pip install scapy"
            )
            return False

        if not self.load_model():
            return False

        self._start_ai_process()
        self.flow_manager.clear()
        self._running = True
        self._last_pps_chk = time.time()
        self._zero_traffic_cycles = 0

        self.logger.warning(
            "Scapy: Captura de pacotes operando com privilégios elevados (admin/root)."
        )

        if self._analyze_thread is None or not self._analyze_thread.is_alive():
            self._analyze_thread = threading.Thread(
                target=self._analysis_loop, daemon=True
            )
            self._analyze_thread.start()

        if self._sniffer_thread is None or not self._sniffer_thread.is_alive():
            self._sniffer_thread = threading.Thread(
                target=self._sniffer_supervisor, args=(iface,), daemon=True
            )
            self._sniffer_thread.start()

        return True

    def _sniffer_supervisor(self, iface):
        backoff = 2
        kwargs = {
            "prn": self.flow_manager.process_packet,
            "store": False,
            "filter": "ip or ip6",
        }
        if iface:
            kwargs["iface"] = iface

        while self._running:
            try:
                self.sniffer = AsyncSniffer(**kwargs)
                self.sniffer.start()
                self.status_changed.emit("🔍 Captura iniciada…")
                self.logger.info(f"Sniffer iniciado em '{iface or 'default'}'")
                backoff = 2

                while self._running and self.sniffer.running:
                    time.sleep(2)

                if not self._running:
                    break

                self.logger.warning("Sniffer parou inesperadamente.")
                self.status_changed.emit("⚠️ Conexão perdida. Reconectando…")

            except Exception as e:
                self.logger.error(f"Falha ao iniciar sniffer: {e}")
                self.status_changed.emit(f"⏳ Falha de rede. Tentando em {backoff}s…")

            if self._running:
                time.sleep(backoff)
                backoff = min(60, backoff * 2)

    def stop(self):
        self._running = False
        if self.sniffer and self.sniffer.running:
            try:
                self.sniffer.stop()
            except Exception:
                pass

        if self._ai_proc and self._ai_proc.is_alive():
            self._in_q.put("STOP")
            self._ai_proc.join(timeout=2)
            if self._ai_proc.is_alive():
                self._ai_proc.terminate()

        if self._analyze_thread and self._analyze_thread.is_alive():
            self._analyze_thread.join(timeout=2.0)
            
        if self._sniffer_thread and self._sniffer_thread.is_alive():
            self._sniffer_thread.join(timeout=2.0)

        self.attack_manager.clear_blocked_states()
        self.status_changed.emit("🛑 Monitoramento interrompido.")

    # --- Loop Central de Análise ---

    def _analysis_loop(self):
        while self._running:
            try:
                time.sleep(1)

                snapshot_count, last_reset = self.flow_manager.get_and_reset_pkt_count()
                now = time.time()
                elapsed = now - last_reset
                
                # Garante um tempo mínimo para evitar divisão por zero ou PPS irreal
                pps = snapshot_count / max(elapsed, 0.001)
                self.pps_updated.emit(float(pps))

                if snapshot_count == 0:
                    self._zero_traffic_cycles += 1
                    if self._zero_traffic_cycles == 10 and not self._warned_no_traffic:
                        self._warned_no_traffic = True
                        self.status_changed.emit(
                            "⚠️ Nenhum tráfego detectado. Tente trocar a Interface na aba CONFIG."
                        )
                else:
                    self._zero_traffic_cycles = 0
                    if self._warned_no_traffic:
                        self._warned_no_traffic = False
                        self.status_changed.emit("✅ Tráfego de rede detectado.")

                if pps > 0:
                    if self._baseline_pps == 0:
                        self._baseline_pps = pps
                    else:
                        self._baseline_pps = (0.90 * self._baseline_pps) + (0.10 * pps)

                self._evaluate_threat_pipeline()

                if now - self._last_cleanup_time >= 60.0:
                    self._last_cleanup_time = now
                    self.flow_manager.cleanup_memory()  # limpa fluxos expirados
                    self.attack_manager.cleanup_memory()

            except Exception as e:
                err_msg = f"Erro na thread de análise: {e}\n{traceback.format_exc()}"
                self.logger.error(err_msg)
                self.error_occurred.emit(err_msg)
                time.sleep(2)

    def _evaluate_threat_pipeline(self):
        """Pipeline principal: roteia dos Fluxos → Motor IA → Avaliação de Risco → Eventos Visuais."""
        now = time.time()

        # 1. Recuperar fluxos ativos
        flow_work_list, expired = self.flow_manager.get_flows_for_analysis()

        # 2. Expirar os mortos
        self.flow_manager.remove_flows(expired)

        # 3. Extrair e computar features via worker IA
        to_analyze_keys, to_analyze_feats = self.flow_manager.batch_extract_features(
            flow_work_list
        )
        if to_analyze_feats:
            batch_results = self._predict_batch(to_analyze_feats)
            self.flow_manager.apply_batch_results(to_analyze_keys, batch_results, now)

        # 4. Avaliacao de Ameaças
        ui_results, to_block, to_log, to_norm = self.attack_manager.evaluate_flows(
            flow_work_list, self._auto_block_enabled
        )

        # 5. Despachar Eventos e Ações Corretivas
        for ip, pps in to_block:
            self.block_requested.emit(ip, pps)
            # Enfileira para o worker em vez de criar uma thread por IP
            self._block_queue.put((ip, pps))

        for ip, (lbl, conf) in to_log.items():
            self.attack_started.emit(ip, lbl.name)

        for ip in to_norm:
            self.attack_normalized.emit(
                {"src_ip": ip, "time": datetime.now().strftime("%H:%M:%S")}
            )

        total_active = len(ui_results)
        total_attacks = 0

        for res in ui_results:
            if res.is_attack:
                total_attacks += 1

        # Ordenar: ataques primeiro, depois fluxo mais recente
        ui_results.sort(key=lambda x: (x.is_attack, x.time), reverse=True)
        top_50 = ui_results[:50]

        self.flow_batch_ready.emit(top_50, total_active, total_attacks)

    def _predict_batch(
        self, feats_list: list[np.ndarray]
    ) -> list[tuple["DetectionStatus", float, bool]]:
        """Gerencia as filas do processo da IA assíncrona com isolamento por req_id."""
        if not feats_list:
            return []

        # Watchdog: Se o processo morreu, reinicia imediatamente
        if not self._ai_proc or not self._ai_proc.is_alive():
            self._start_ai_process()
            # Pequena pausa para o processo carregar o modelo no primeiro arranque
            time.sleep(0.5)

        try:
            req_id = time.time_ns()
            threshold = self._ai_thresholds.get(self._profile, -0.15)
            feats_combined = np.array(feats_list)

            # Envia requisição
            self._in_q.put((req_id, feats_combined, threshold))

            # Aguarda pela resposta correspondente ao ID atual
            # Retries para o caso de mensagens de timeout anteriores estarem na frente
            for _ in range(5): 
                try:
                    resp_id, status, data = self._out_q.get(timeout=1.5)
                    
                    if resp_id != req_id:
                        self.logger.debug(f"IA: Ignorando resposta antiga {resp_id}")
                        continue  # Descarta resposta de requisição anterior (stale)

                    if status == "OK":
                        if len(data) != len(feats_list):
                            self.logger.error("Dessincronização IA: tamanho da resposta inválido.")
                            return [(DetectionStatus.ERROR, 0.0, False)] * len(feats_list)
                        return data
                    else:
                        self.logger.error(f"Erro no worker IA: {data}")
                        break
                except queue.Empty:
                    continue  # Tenta novamente até o limite de retries

            self.logger.warning("IA: Timeout ou erro após retitativas.")
            return [(DetectionStatus.ERROR, 0.0, False)] * len(feats_list)

        except Exception as e:
            self.logger.error(f"Erro fatal na comunicação com worker IA: {e}")
            return [(DetectionStatus.ERROR, 0.0, False)] * len(feats_list)
