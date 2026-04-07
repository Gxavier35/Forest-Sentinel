import platform
import os
import ctypes
import sys
from datetime import datetime
import ipaddress


def get_root_dir():
    """Retorna o diretório base (suporta PyInstaller)."""
    here = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return here if getattr(sys, "frozen", False) else os.path.dirname(here)


def get_exe_dir():
    """Retorna o diretório do executável final ou da raiz se for script."""
    root = get_root_dir()
    return os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else root


def get_asset_path(name: str) -> str:
    """Retorna o caminho completo de um asset."""
    return os.path.join(get_root_dir(), "assets", name)


def get_timestamp() -> str:
    """Retorna o timestamp atual no formato padrão HH:MM:SS."""
    return datetime.now().strftime("%H:%M:%S")


def get_proto_name(proto_id: int) -> str:
    """Retorna o nome do protocolo (TCP, UDP ou ID bruto)."""
    return {6: "TCP", 17: "UDP"}.get(proto_id, str(proto_id))


def format_flow_key(flow_tuple: tuple) -> str:
    """Formata uma tupla flow_key (src_ip, dst_ip, src_port, dst_port, proto) em string visual."""
    src_ip, dst_ip, src_port, dst_port, proto = flow_tuple
    p_name = get_proto_name(proto)
    return f"{src_ip}:{src_port} → {dst_ip}:{dst_port} [{p_name}]"


def is_private_ip(ip: str) -> bool:
    """Verifica se um endereço IP pertence a uma rede privada (RFC 1918)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def is_admin() -> bool:
    """Verifica se o processo tem privilégios de Administrador/Root."""
    try:
        os_name = platform.system().lower()
        if os_name == "windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.getuid() == 0
    except Exception:
        return False


# --- Atallhos Confortáveis para Recursos --- #
RES_ICON = get_asset_path("icon.png")
RES_LOGO = get_asset_path("logo.png")
RES_FLAG_BR = get_asset_path("flag_br.png")
RES_FLAG_US = get_asset_path("flag_us.png")
