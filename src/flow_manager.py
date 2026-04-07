"""
flow_manager.py
---------------
Gerenciador de Estado Bruto de Rede.
Responsável por alocar fluxos, realizar packet callbacks puros e gerenciar eviction.
"""

import time
import collections
import threading
import itertools

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

    def add(self, pkt_info: dict):
        self.packets.append(pkt_info)
        self.last_seen = time.time()


class FlowManager:
    """Centraliza a memória de fluxos e coordena a extração de métricas (Features)."""

    _MULTICAST_PREFIXES_V4 = ("224.", "239.", "255.")
    _MULTICAST_PREFIXES_V6 = ("ff00::",)

    def __init__(self):
        self._flows: dict[tuple, FlowRecord] = {}
        self._lock = threading.RLock()

        # Estatísticas de pacote bruto capturado na callback
        self._pkt_count = 0
        self._pkt_lock = threading.Lock()

    def get_and_reset_pkt_count(self) -> int:
        with self._pkt_lock:
            c = self._pkt_count
            self._pkt_count = 0
            return c

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
                elif rev in self._flows:
                    direction, flow_key = "bwd", rev
                else:
                    direction, flow_key = "fwd", key

                    if len(self._flows) >= MAX_FLOWS:
                        # Otimização em lote: limpeza rápida sob estresse/DDoS
                        try:
                            oldest_created = list(
                                itertools.islice(self._flows.keys(), 100)
                            )
                            oldest_created.sort(
                                key=lambda k: self._flows.get(k, self).last_seen
                            )
                            for k in oldest_created[:50]:
                                self._flows.pop(k, None)
                        except Exception:
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
        except Exception:
            pass

    def cleanup_memory(self):
        """Remove fluxos obsoletos a mais de FLOW_TIMEOUT sem interação."""
        now = time.time()
        to_remove = []
        with self._lock:
            for k, rec in self._flows.items():
                if (now - rec.last_seen) > FLOW_TIMEOUT:
                    to_remove.append(k)
            for k in to_remove:
                self._flows.pop(k, None)
        return to_remove

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
                    flow_work_list.append(
                        (
                            fk,
                            rec,
                            list(rec.packets),
                            rec.last_seen,
                            rec.last_analyzed,
                            rec.last_result,
                        )
                    )

        return flow_work_list, expired

    def batch_extract_features(self, flow_work_list) -> tuple:
        """Gera vetores para análise pela IA e aplica throttling de desempenho sazonal."""
        need_analysis = []
        for fk, rec, pkts_snap, ls_snap, la_snap, lr_snap in flow_work_list:
            if len(pkts_snap) < MIN_PKTS:
                continue
            pkts_len = len(pkts_snap)

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
        for fk, rec, pkts_snap in need_analysis:
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
