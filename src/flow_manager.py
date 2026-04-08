"""
flow_manager.py
---------------
Gerenciador de Estado Bruto de Rede.
Responsável por alocar fluxos, realizar packet callbacks puros e gerenciar eviction.
"""

import time
import collections
import threading
import logging

import numpy as np
from constants import (
    MAX_PKTS_FLOW,
    MAX_FLOWS,
    FLOW_TIMEOUT,
    MAX_ANALYZE_PER_SEC,
    MIN_PKTS,
)
from features import compute_features

try:
    from scapy.all import IP, IPv6, TCP, UDP
except ImportError:
    pass


class FlowRecord:
    """Mantém os pacotes de um fluxo bidirecional e o controle de estado."""

    def __init__(self):
        self.packets = collections.deque(maxlen=MAX_PKTS_FLOW)
        self.last_seen = time.time()
        self.last_analyzed = 0.0
        self.last_analyzed_count = 0
        self.last_result = None  # (label, confidence, is_attack)
        self.is_dirty = True     # Indica se houve atividade nova desde a última detecção de limites

    def add(self, pkt_info: dict):
        self.packets.append(pkt_info)
        self.last_seen = time.time()
        self.is_dirty = True


class FlowManager:
    """Centraliza a memória de fluxos e coordena a extração de métricas (Features)."""

    _MULTICAST_PREFIXES_V4 = ("224.", "239.", "255.")
    _MULTICAST_PREFIXES_V6 = ("ff00::",)

    def __init__(self):
        # Usamos OrderedDict para manter a ordem LRU (Least Recently Used) de forma eficiente
        self._flows: collections.OrderedDict[tuple, FlowRecord] = collections.OrderedDict()
        self._lock = threading.RLock()

        # Estatísticas de pacote bruto capturado na callback
        self._pkt_count = 0
        self._last_pkt_reset = time.time()
        self._pkt_lock = threading.Lock()
        self.logger = logging.getLogger("FlowManager")

    def get_and_reset_pkt_count(self) -> tuple[int, float]:
        with self._pkt_lock:
            c = self._pkt_count
            t = self._last_pkt_reset
            self._pkt_count = 0
            self._last_pkt_reset = time.time()
            return c, t

    def clear(self):
        with self._lock:
            self._flows.clear()

    def process_packet(self, pkt):
        """Invocado em altíssima frequência para rotear pacotes raw da rede."""
        with self._pkt_lock:
            self._pkt_count += 1

        try:
            if pkt.haslayer(IP):
                ip_layer = pkt[IP]
            elif pkt.haslayer(IPv6):
                ip_layer = pkt[IPv6]
            else:
                return

            proto = ip_layer.nh if pkt.haslayer(IPv6) else ip_layer.proto
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            if pkt.haslayer(IP) and any(
                dst_ip.startswith(p) for p in self._MULTICAST_PREFIXES_V4
            ):
                return
            if pkt.haslayer(IPv6) and any(
                dst_ip.lower().startswith(p) for p in self._MULTICAST_PREFIXES_V6
            ):
                return

            src_port, dst_port = 0, 0
            tcp_flags, tcp_window = None, None
            ip_header_len = (
                ip_layer.ihl * 4 if pkt.haslayer(IP) and ip_layer.ihl else 20
            )
            pkt_len = len(pkt)

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                src_port, dst_port = tcp.sport, tcp.dport
                tcp_flags, tcp_window = int(tcp.flags), tcp.window
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                src_port, dst_port = udp.sport, udp.dport

            key = (src_ip, dst_ip, src_port, dst_port, proto)
            rev = (dst_ip, src_ip, dst_port, src_port, proto)

            with self._lock:
                if key in self._flows:
                    direction, flow_key = "fwd", key
                    self._flows.move_to_end(key)  # Marca como mais recente
                elif rev in self._flows:
                    direction, flow_key = "bwd", rev
                    self._flows.move_to_end(rev)  # Marca como mais recente
                else:
                    direction, flow_key = "fwd", key

                    if len(self._flows) >= MAX_FLOWS:
                        # Expulsão LRU O(1): remove os 50 itens mais antigos instantaneamente
                        try:
                            for _ in range(50):
                                self._flows.popitem(last=False)
                        except (Exception, KeyError):
                            pass

                    self._flows[flow_key] = FlowRecord()

                self._flows[flow_key].add(
                    {
                        "time": float(pkt.time),
                        "length": pkt_len,
                        "ip_header_len": ip_header_len,
                        "tcp_flags": tcp_flags,
                        "tcp_window": tcp_window,
                        "direction": direction,
                    }
                )
        except Exception as e:
            self.logger.debug(f"Pkt process error: {e}")

    def cleanup_memory(self, max_to_clean=500):
        """
        Remove fluxos obsoletos de forma incremental.
        Aproveita o OrderedDict (LRU) para Early Break: para assim que encontrar um fluxo ativo.
        """
        now = time.time()
        keys_to_del = []
        
        with self._lock:
            # OrderedDict.items() mantém a ordem de inserção/move_to_end.
            # O início da lista contém os fluxos mais antigos (Least Recently Used).
            for i, (k, rec) in enumerate(self._flows.items()):
                if i >= max_to_clean:
                    break
                    
                if (now - rec.last_seen) > FLOW_TIMEOUT:
                    keys_to_del.append(k)
                else:
                    # Early Break 🚀: Se este fluxo não expirou, nenhum dos
                    # seguintes (que são mais novos) expirou também.
                    break
            
            for k in keys_to_del:
                self._flows.pop(k, None)
                
        return keys_to_del

    def get_flows_for_analysis(self) -> tuple:
        """
        Retorna listas para envio da inferência e a camada temporária de apresentação.
        Evita duplicação do dicionário principal projetando apenas a snapshot.
        """
        now = time.time()
        with self._lock:
            flow_work_list = []
            expired = []

            for fk, rec in self._flows.items():
                if (now - rec.last_seen) > FLOW_TIMEOUT:
                    expired.append(fk)
                else:
                    # Passamos a deque original. A conversão para list() será retardada (Lazy Copy)
                    # para evitar alocações de memória massivas e desnecessárias.
                    flow_work_list.append(
                        (
                            fk,
                            rec,
                            rec.packets, # Referência direta à deque
                            rec.last_seen,
                            rec.last_analyzed,
                            rec.last_result,
                            rec.is_dirty
                        )
                    )

        return flow_work_list, expired

    def batch_extract_features(self, flow_work_list) -> tuple:
        """Gera vetores para análise pela IA e aplica throttling de desempenho sazonal."""
        need_analysis = []
        for fk, rec, pkts_snap, ls_snap, la_snap, lr_snap, is_dirty in flow_work_list:
            if len(pkts_snap) < MIN_PKTS:
                continue
            pkts_len = len(pkts_snap)

            # Otimização Crítica 🚀: Se não teve atividade nova (is_dirty=False) e já foi analisado, pula.
            if not is_dirty and la_snap != 0:
                continue

            if (
                la_snap == 0
                or (pkts_len - rec.last_analyzed_count) >= 10
                or (
                    pkts_len == MAX_PKTS_FLOW
                    and rec.last_analyzed_count < MAX_PKTS_FLOW
                )
            ):
                need_analysis.append((fk, rec, pkts_snap))

        need_analysis.sort(key=lambda x: len(x[2]), reverse=True)
        need_analysis = need_analysis[:MAX_ANALYZE_PER_SEC]

        to_analyze_keys = []
        to_analyze_feats = []
        for fk, rec, pkts_deque in need_analysis:
            # Sincronização Final: Converte para lista apenas para o subset que SERÁ analisado
            pkts_snap = list(pkts_deque)
            feats = compute_features(fk, pkts_snap)
            if feats is not None:
                to_analyze_keys.append(fk)
                to_analyze_feats.append(feats)

        return to_analyze_keys, to_analyze_feats

    def apply_batch_results(self, to_analyze_keys, batch_results, timestamp):
        """Aplica os resultados assíncronos do engine back-end de volta à memória do fluxo."""
        with self._lock:
            for i, fk in enumerate(to_analyze_keys):
                if i >= len(batch_results):
                    break  # Proteção extra: ignora caso as keys ultrapassem os results
                obj = self._flows.get(fk)
                if obj:
                    obj.last_result = batch_results[i]
                    obj.last_analyzed = timestamp
                    obj.last_analyzed_count = len(obj.packets)

    def remove_flows(self, keys):
        """Remove explicit keys from tracking."""
        with self._lock:
            for k in keys:
                self._flows.pop(k, None)
