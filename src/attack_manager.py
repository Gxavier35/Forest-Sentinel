"""
attack_manager.py
-----------------
Gerenciador de Estados de Ataque.
Determina limiares de bloqueio, tracking temporal e mantém a Whitelist.
"""

import time
import ipaddress
import threading
import os
import logging
from utils import get_root_dir, get_timestamp, get_proto_name, format_flow_key
from constants import (
    DetectionStatus,
    LEVEL1_SECS,
    LEVEL2_SECS,
    BLOCK_PERSIST_SECS,
    NORMALIZE_SECS,
    FlowResult,
)

WHITELIST_FILE = os.path.join(get_root_dir(), "config", "whitelist.txt")


class AttackStateManager:
    """Consolida as listas de bloqueio, tracking temporizado das ameaças e a Whitelist central."""

    def __init__(self):
        self._lock = threading.RLock()
        self.logger = logging.getLogger("AttackManager")

        self._attack_persist: dict[str, float] = {}
        self._last_seen_attack: dict[str, float] = {}
        self._last_block_attempt: dict[str, float] = {}
        self._blocked_status: dict[str, dict] = {}
        self._logged_attacks_engine = set()

        self._whitelist: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
        self._whitelist_ips: set[str] = set()
        self._load_whitelist()

    # --- Whitelist Management --- #

    def _load_whitelist(self):
        with self._lock:
            self._whitelist = set()
            self._whitelist_ips = set()
            if not os.path.exists(WHITELIST_FILE):
                return
            try:
                with open(WHITELIST_FILE, "r") as f:
                    for line in f:
                        entry = line.strip()
                        if not entry or entry.startswith("#"):
                            continue
                        try:
                            net = ipaddress.ip_network(entry, strict=False)
                            self._whitelist.add(net)
                            if net.num_addresses == 1:
                                self._whitelist_ips.add(str(net.network_address))
                        except ValueError:
                            self.logger.warning(
                                f"IP/Rede inválida na whitelist: {entry}"
                            )
            except Exception as e:
                self.logger.error(f"Erro ao ler whitelist: {e}")

    def _save_whitelist(self):
        os.makedirs(os.path.dirname(WHITELIST_FILE), exist_ok=True)
        try:
            with open(WHITELIST_FILE, "w") as f:
                # Ordena para manter o arquivo determinístico
                for net in sorted(self._whitelist, key=lambda x: str(x)):
                    f.write(str(net) + "\n")
        except Exception as e:
            self.logger.error(f"Erro ao salvar whitelist: {e}")

    def add_to_whitelist(self, val: str) -> bool:
        val = val.strip()
        if not val: return False
        try:
            net = ipaddress.ip_network(val, strict=False)
            with self._lock:
                if net not in self._whitelist:
                    self._whitelist.add(net)
                    if net.num_addresses == 1:
                        self._whitelist_ips.add(str(net.network_address))
                    self._save_whitelist()
                    return True
        except ValueError:
            pass
        return False

    def remove_from_whitelist(self, val: str) -> bool:
        val = val.strip()
        if not val: return False
        try:
            net = ipaddress.ip_network(val, strict=False)
            with self._lock:
                # 1. Tentar remoção por objeto (mais rápido)
                if net in self._whitelist:
                    self._whitelist.remove(net)
                    if net.num_addresses == 1:
                        self._whitelist_ips.discard(str(net.network_address))
                    self._save_whitelist()
                    return True
                
                # 2. Fallback por comparação de string (casos de normalização/objetos diferentes)
                to_remove = None
                for ex in self._whitelist:
                    if str(ex) == str(net):
                        to_remove = ex
                        break
                
                if to_remove:
                    self._whitelist.remove(to_remove)
                    if to_remove.num_addresses == 1:
                        self._whitelist_ips.discard(str(to_remove.network_address))
                    self._save_whitelist()
                    return True
        except ValueError:
            pass
        return False

    def clear_whitelist(self):
        with self._lock:
            self._whitelist.clear()
            self._whitelist_ips.clear()
            self._save_whitelist()

    def get_whitelist_items(self) -> list[str]:
        # Retorna lista ordenada para consistência na UI
        with self._lock:
            return sorted([str(net) for net in self._whitelist])

    def is_whitelisted(self, src_ip: str) -> bool:
        with self._lock:
            if src_ip in self._whitelist_ips:
                return True
            try:
                ip_obj = ipaddress.ip_address(src_ip)
                for net in self._whitelist:
                    if ip_obj in net:
                        return True
            except (ValueError, TypeError):
                pass
        return False

    # --- Tracking & State Transition --- #

    def cleanup_memory(self):
        """Remove bloqueios globais expirados (>24h). O sincronismo de estado temporal ocorre durante a avaliação."""
        now = time.time()
        with self._lock:
            expired_blocks = [
                ip
                for ip, info in self._blocked_status.items()
                if (now - info.get("block_time", now)) > 86400
            ]
            for ip in expired_blocks:
                self._blocked_status.pop(ip, None)

    def evaluate_flows(self, flow_work_list: list, autoblock_enabled: bool = True) -> list[FlowResult]:
        """
        Avalia cada fluxo buscando ameaças por limiar e persistência.
        Retorna lista de resultados formatados para a UI.
        """
        now = time.time()
        ui_results = []
        to_block = []
        to_norm = []
        to_log = {}
        active_ips = set()
        current_cycle_attacks = {}

        for fk, rec, pkts_snap, ls_snap, la_snap, lr_snap, is_dirty in flow_work_list:
            src_ip, dst_ip, src_port, dst_port, proto = fk
            active_ips.add(src_ip)

            # Otimização: Se o fluxo não teve atividade nova, pegamos os resultados estáveis
            # Mas ainda precisamos retornar o FlowResult para a UI não "parcar".
            lr_fresh = rec.last_result
            label, confidence, is_attack = (
                lr_fresh if lr_fresh else (DetectionStatus.NORMAL, 0.0, False)
            )
            proto_name = get_proto_name(proto)

            if self.is_whitelisted(src_ip):
                is_attack, label = False, DetectionStatus.NORMAL

            # Reset do dirty flag: a análise de um ciclo "consome" a novidade do fluxo
            rec.is_dirty = False

            # Otimização Crítica: Se não há pacotes novos, as estatísticas de limiar não mudaram.
            # No entanto, ainda precisamos calcular a UI result para manter o fluxo visível.
            dur_secs = float(pkts_snap[-1]["time"] - pkts_snap[0]["time"]) if len(pkts_snap) > 1 else 0.0
            pkts_per_sec = len(pkts_snap) / dur_secs if dur_secs > 0 else 0.0

            is_final_attack = False
            if is_attack:
                with self._lock:
                    start_time = self._attack_persist.get(src_ip, now)
                dur = now - start_time

                if dur >= LEVEL2_SECS:
                    label, is_final_attack = DetectionStatus.ATTACK, True
                    if src_ip not in self._logged_attacks_engine:
                        to_log[src_ip] = (label, confidence)
                elif dur >= LEVEL1_SECS:
                    label, is_final_attack = DetectionStatus.SUSPICIOUS, False
                else:
                    label, is_final_attack = DetectionStatus.NORMAL, False

                current_cycle_attacks[src_ip] = pkts_per_sec

            # Passa a responsabilidade de formatter para a UI / Orchestrator.
            # Retorna raw values padronizados como Dataclass.
            ui_results.append(
                FlowResult(
                    flow_tuple=fk,
                    flow_key=format_flow_key(fk),
                    src_ip=src_ip,
                    label=label.name,
                    is_attack=is_final_attack,
                    confidence=confidence,
                    pkts=len(pkts_snap),
                    duration=dur_secs,
                    proto=proto_name,
                    time=get_timestamp(),
                )
            )

        # 1. Atualizar persistência
        with self._lock:
            for s_ip, pps in current_cycle_attacks.items():
                if s_ip not in self._attack_persist:
                    self._attack_persist[s_ip] = now
                self._last_seen_attack[s_ip] = now

                if autoblock_enabled and s_ip not in self._blocked_status:
                    if (now - self._attack_persist[s_ip]) >= BLOCK_PERSIST_SECS:
                        last_att = self._last_block_attempt.get(s_ip, 0)
                        if now - last_att > 10.0:
                            self._last_block_attempt[s_ip] = now
                            to_block.append((s_ip, pps))

            # 2. Normalização
            norm_ips = [
                ip
                for ip, ls in self._last_seen_attack.items()
                if (now - ls) > NORMALIZE_SECS
            ]
            for ip in norm_ips:
                self._attack_persist.pop(ip, None)
                self._last_seen_attack.pop(ip, None)
                self._last_block_attempt.pop(ip, None)
                self._logged_attacks_engine.discard(ip)
                to_norm.append(ip)

            for ip, (lbl, conf) in to_log.items():
                self._logged_attacks_engine.add(ip)

            # 3. Sincroniza tracking de IPs ativos de forma robusta
            self._get_stale_from_tracking_locked(active_ips)

        return ui_results, to_block, to_log, to_norm

    # --- Block States Accessors --- #

    def set_blocking_placeholder(self, src_ip: str, pps: float):
        with self._lock:
            if src_ip not in self._blocked_status:
                self._blocked_status[src_ip] = {
                    "pps": pps,
                    "time": "Bloqueando...",
                    "block_time": time.time(),
                }

    def confirm_block(self, src_ip: str, pps: float) -> str:
        with self._lock:
            ts = get_timestamp()
            self._blocked_status[src_ip] = {
                "pps": pps,
                "time": ts,
                "block_time": time.time(),
            }
            return ts

    def remove_blocked_status(self, src_ip: str):
        with self._lock:
            self._blocked_status.pop(src_ip, None)
            self._attack_persist.pop(src_ip, None)

    def is_block_pending_or_active(self, src_ip: str) -> bool:
        with self._lock:
            status = self._blocked_status.get(src_ip)
            return status is not None and status.get("time") != "Bloqueando..."

    def clear_blocked_states(self):
        with self._lock:
            self._blocked_status.clear()
            self._attack_persist.clear()

    def get_blocked_snapshot(self) -> dict:
        with self._lock:
            return dict(self._blocked_status)

    def get_stale_from_tracking(self, active_flow_ips) -> list:
        """Versão pública com lock fixo."""
        with self._lock:
            return self._get_stale_from_tracking_locked(active_flow_ips)

    def _get_stale_from_tracking_locked(self, active_flow_ips) -> list:
        """Limpa o tracking de IPs que não possuem mais fluxos ativos (Assume lock adquirido)."""
        # Otimização: Converter para set para busca O(1)
        active_set = set(active_flow_ips)
        stale = [ip for ip in self._attack_persist if ip not in active_set]
        for ip in stale:
            self._attack_persist.pop(ip, None)
            self._last_seen_attack.pop(ip, None)
        return stale
