import platform
import os
import ctypes

import sys


def get_root_dir():
    """Retorna o diretório base (suporta PyInstaller)."""
    here = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return here if getattr(sys, "frozen", False) else os.path.dirname(here)


def get_exe_dir():
    """Retorna o diretório do executável final ou da raiz se for script."""
    root = get_root_dir()
    return os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else root


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
