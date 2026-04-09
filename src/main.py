"""
main.py
-------
Entry point do Forest Sentinel.
Execute como Administrador para que o Scapy possa capturar pacotes.
"""

import sys
import os
import logging
from logging.handlers import RotatingFileHandler

import multiprocessing
from utils import is_admin, get_root_dir

_ROOT = get_root_dir()

if getattr(sys, "frozen", False):
    _LOG_DIR = os.path.join(os.path.dirname(sys.executable), "logs")
else:
    _LOG_DIR = os.path.join(_ROOT, "logs")

if not os.path.exists(_LOG_DIR):
    os.makedirs(_LOG_DIR, exist_ok=True)

_LOG_PATH = os.path.join(_LOG_DIR, "ddos_monitor.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(name)s] - %(message)s",
    handlers=[
        RotatingFileHandler(
            _LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
        ),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("Main")


from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtGui import QIcon, QDesktopServices
from PyQt6.QtCore import Qt, QUrl

from dashboard import MainWindow


def handle_exception(exc_type, exc_value, exc_traceback):
    """Log de erros fatais não capturados."""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    logger.critical(
        "Erro fatal não capturado!", exc_info=(exc_type, exc_value, exc_traceback)
    )


sys.excepthook = handle_exception


def check_npcap():
    """Tenta detectar se o Npcap/WinPcap está instalado (necessário para o Scapy)."""
    if sys.platform != "win32":
        return True
    system32 = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32")
    wpcap = os.path.join(system32, "wpcap.dll")
    return os.path.exists(wpcap)


def main():
    if sys.platform == "win32" and not is_admin():
        import ctypes

        logger.info("Privilégios insuficientes. Solicitando elevação UAC...")
        import subprocess

        args_str = subprocess.list2cmdline(sys.argv)
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, args_str, None, 0
        )
        sys.exit(0)

    logger.info("--- Iniciando Forest Sentinel ---")

    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("Forest Sentinel")
    app.setOrganizationName("IAtreinada")

    if not check_npcap():
        logger.warning("Npcap não detectado. Exibindo alerta ao usuário.")
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setWindowTitle("Requisito de Sistema (Npcap)")
        msg.setText("O Forest Sentinel requer o driver de rede Npcap para interceptar o tráfego de rede e detectar ataques.\n\nComo o Npcap não foi detectado no seu computador, a captura de pacotes não funcionará corretamente.\nDeseja ser redirecionado para a página oficial para baixar o driver agora?")
        msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Ignore | QMessageBox.StandardButton.Abort)
        
        btn_yes = msg.button(QMessageBox.StandardButton.Yes)
        btn_yes.setText("Sim, baixar Npcap")
        btn_ignore = msg.button(QMessageBox.StandardButton.Ignore)
        btn_ignore.setText("Ignorar (Pode falhar)")
        btn_abort = msg.button(QMessageBox.StandardButton.Abort)
        btn_abort.setText("Sair")
        
        msg.setDefaultButton(QMessageBox.StandardButton.Yes)
        
        reply = msg.exec()
        if reply == QMessageBox.StandardButton.Yes:
            QDesktopServices.openUrl(QUrl("https://npcap.com/"))
            sys.exit(0)
        elif reply == QMessageBox.StandardButton.Abort:
            sys.exit(0)

    icon_path = os.path.join(_ROOT, "assets", "icon.png")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    window = MainWindow()
    window.showMaximized()

    sys.exit(app.exec())


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
