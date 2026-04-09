"""
constants.py
------------
Definições de constantes, limites sistêmicos e status.
"""

from enum import IntEnum
from dataclasses import dataclass


@dataclass
class FlowResult:
    __slots__ = (
        "flow_tuple", "flow_key", "src_ip", "label", "is_attack", 
        "confidence", "pkts", "duration", "proto", "time"
    )
    flow_tuple: tuple
    flow_key: str
    src_ip: str
    label: str
    is_attack: bool
    confidence: float
    pkts: int
    duration: float
    proto: str
    time: str


class DetectionStatus(IntEnum):
    NORMAL = 0
    SUSPICIOUS = 1
    ATTACK = 2
    ERROR = 3


# Limites de Fluxo e Rede
FLOW_TIMEOUT = 10  # Segundos sem pacote -> fluxo encerrado
MIN_PKTS = 5  # Mínimo de pacotes para invocar inferência IA
MAX_FLOWS = 5000  # Limite do dicionário em memória
MAX_PKTS_FLOW = 100  # Limite histórico de pacotes retido por fluxo na queue
MAX_ANALYZE_PER_SEC = (
    300  # Cota de uso da CPU (quantos fluxos máximos analisados por ciclo)
)

# Temporizadores de Estado de Ataque e UI
LEVEL1_SECS = 30.0  # ANALISANDO (Amarelo)
LEVEL2_SECS = 60.0  # POSSÍVEL ATAQUE (Vermelho)
BLOCK_PERSIST_SECS = 90.0  # Tempo retido como ofensor antes de bloqueio auto
NORMALIZE_SECS = 30.0  # Tempo inativo sem labels de ataque para ser perdoado
