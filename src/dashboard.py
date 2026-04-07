"""
dashboard.py
------------
Interface principal do Forest Sentinel.
"""

import sys
import os
import csv
import logging
import collections
from datetime import datetime

from PyQt6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QSplitter,
    QApplication,
    QTabWidget,
    QMessageBox,
    QSystemTrayIcon,
    QFileDialog,
    QMenu,
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QEvent
from PyQt6.QtGui import QColor, QFont, QBrush, QIcon, QPixmap, QPainter, QAction


class ScapyLoaderThread(QThread):
    finished = pyqtSignal(list, str)

    def run(self):
        try:
            from scapy.all import conf, get_working_ifaces

            ifaces = get_working_ifaces()
            res = [(i.description if i.description else i.name, i.name) for i in ifaces]
            self.finished.emit(res, conf.iface.name)
        except Exception:
            self.finished.emit([], "")


from ui_tabs import OperationTab, ConfigurationTab, BlockedTab, WhitelistTab
from monitor_engine import MonitorEngine
from ui_components import COLORS, MetricCard, ActivityChart, AlertBanner

# R8: import get_firewall_manager removido — manager e criado dentro do MonitorEngine
from utils import is_admin, get_root_dir
from config_manager import load_config, save_config

_ROOT = get_root_dir()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Forest Sentinel")
        self.setMinimumSize(1280, 800)

        # Configuração do Ícone da Janela
        icon_path = os.path.join(_ROOT, "assets", "icon.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self._apply_global_style()

        self.logger = logging.getLogger("UI")

        self._start_time = datetime.now()
        self._attack_history = collections.deque(maxlen=500)
        self._config = load_config()
        self._engine = MonitorEngine()
        self._load_settings_to_engine()

        self._engine.pps_updated.connect(self._on_pps_updated)
        self._engine.ip_blocked.connect(self._on_ip_blocked)
        self._engine.ip_unblocked.connect(self._on_ip_unblocked)
        self._engine.block_requested.connect(self._on_block_requested)
        self._engine.status_changed.connect(self._on_status)
        self._engine.error_occurred.connect(self._on_error)
        self._engine.whitelist_changed.connect(self._on_whitelist_changed)
        self._engine.attack_normalized.connect(self._on_attack_normalized)
        self._engine.attack_started.connect(self._on_attack_started)
        self._engine.flow_batch_ready.connect(self._on_flow_batch_ready)
        self._engine.state_sync.connect(self._on_state_sync)

        self._setup_tray()
        self._build_ui()
        self._update_blocked_tab_title()
        self._log_event("🖥️ Interface carregada.", COLORS["text_dim"])

        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._refresh_ui)
        self._refresh_timer.start(1000)

        if not is_admin():
            QTimer.singleShot(1500, self._warn_non_admin)

        # 🚀 AUTO-START: Monitoramento automático opcional através da configuração
        if self._config.get("autostart", True):
            QTimer.singleShot(1000, self._auto_start_monitoring)

    def _apply_global_style(self):
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{
                background-color: {COLORS['bg_deep']};
                color: {COLORS['text']};
                font-family: 'Segoe UI', sans-serif;
            }}
            QTabWidget::pane {{ border: 1px solid {COLORS['border']}; border-top: none; }}
            QTabBar::tab {{
                background: {COLORS['bg_card']};
                color: {COLORS['text_dim']};
                padding: 10px 20px;
                border: 1px solid {COLORS['border']};
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                min-width: 120px;
            }}
            QTabBar::tab:selected {{ color: {COLORS['accent']}; border-top: 2px solid {COLORS['accent']}; }}
            QPushButton {{
                border-radius: 6px; font-weight: bold; padding: 8px 16px;
            }}
        """)

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(15, 15, 15, 15)

        header = QHBoxLayout()
        
        # Logo / Title Container
        logo_container = QWidget()
        logo_layout = QHBoxLayout(logo_container)
        logo_layout.setContentsMargins(0, 0, 0, 0)
        logo_layout.setSpacing(15)

        # Escudo (Logo)
        logo_lbl = QLabel()
        logo_path = os.path.join(_ROOT, "assets", "logo.png")
        if os.path.exists(logo_path):
            pix = QPixmap(logo_path)
            logo_lbl.setPixmap(pix.scaledToHeight(70, Qt.TransformationMode.SmoothTransformation))
            logo_layout.addWidget(logo_lbl)

        # Titulos (Vertical Layout ao lado do logo)
        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)

        # Nome do Programa (Texto)
        title_lbl = QLabel("Forest\nSentinel")
        title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_lbl.setStyleSheet(f"""
            color: {COLORS['accent']};
            font-size: 32px;
            font-weight: 900;
            line-height: 0.8;
            letter-spacing: 1px;
            font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
        """)
        text_layout.addWidget(title_lbl)

        logo_layout.addLayout(text_layout)
        header.addWidget(logo_container)
        header.addStretch()
        self._clock_lbl = QLabel("--:--:--")
        self._clock_lbl.setStyleSheet(f"color: {COLORS['text_dim']}; font-size: 12px;")
        header.addWidget(self._clock_lbl)
        root.addLayout(header)

        m_row = QHBoxLayout()
        m_row.setSpacing(10)
        self._card_total = MetricCard("Ativos", "0", "fluxos", COLORS["accent"])
        self._card_normal = MetricCard("Normal", "0", "fluxos", COLORS["success"])
        self._card_attack = MetricCard("Ataques", "0", "alertas", COLORS["danger"])
        self._card_pkts = MetricCard("Tráfego", "0", "pps", COLORS["warning"])
        for c in [
            self._card_total,
            self._card_normal,
            self._card_attack,
            self._card_pkts,
        ]:
            m_row.addWidget(c)
        root.addLayout(m_row)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)

        self._table = QTableWidget()
        self._table.setColumnCount(7)
        self._table.setHorizontalHeaderLabels(
            [
                "Hora",
                "Fluxo",
                "Proto",
                "Pacotes",
                "Duração",
                "Status",
                "Nível de Ameaça",
            ]
        )
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setShowGrid(False)
        self._table.setStyleSheet(
            f"background: {COLORS['bg_panel']}; border-radius: 8px;"
        )
        left_layout.addWidget(self._table, stretch=3)

        self._chart = ActivityChart()
        left_layout.addWidget(self._chart, stretch=2)
        splitter.addWidget(left_panel)

        self._tabs = QTabWidget()

        self.op_tab = OperationTab(self._engine)

        self.op_tab.start_btn.clicked.connect(self._start_monitor)
        self.op_tab.stop_btn.clicked.connect(self._stop_monitor)
        self.op_tab.export_btn.clicked.connect(self._export_log)
        self.op_tab.clear_btn.clicked.connect(self._clear_log)

        self.cfg_tab = ConfigurationTab(self._engine)
        self._populate_ifaces(self.cfg_tab.iface_combo)
        self._apply_settings_to_ui()

        self.cfg_tab.profile_combo.currentIndexChanged.connect(self._change_profile)
        self.cfg_tab.autoblock_chk.stateChanged.connect(self._toggle_autoblock)
        self.cfg_tab.reset_btn.clicked.connect(self._reset_ai_thresholds)
        self.cfg_tab.update_ifaces_btn.clicked.connect(
            lambda: self._populate_ifaces(self.cfg_tab.iface_combo)
        )
        self.cfg_tab.apply_btn.clicked.connect(self._save_settings)
        self.wl_tab = WhitelistTab(self._engine)
        self.wl_tab.wl_add_btn.clicked.connect(self._add_to_whitelist)
        self.wl_tab.wl_remove_btn.clicked.connect(self._remove_from_whitelist)
        self.wl_tab.wl_clear_btn.clicked.connect(self._clear_whitelist)
        for p_id, (slider, lbl) in self.cfg_tab.ai_controls.items():
            slider.valueChanged.connect(
                lambda v, p=p_id, l=lbl: self._on_threshold_changed(p, v, l)
            )

        self.blocked_tab = BlockedTab(self._engine)
        self.blocked_tab.unblock_all_btn.clicked.connect(self._unblock_all)

        self._tabs.addTab(self.op_tab, "🚀 MONITOR")
        self._tabs.addTab(self.cfg_tab, "⚙ CONFIG")
        self._tabs.addTab(self.blocked_tab, "🔒 BLOQUEADOS")
        self._tabs.addTab(self.wl_tab, "🛡 WHITELIST")

        splitter.addWidget(self._tabs)
        splitter.setSizes([850, 430])
        root.addWidget(splitter)

        self._alert_banner = AlertBanner(central)
        self._alert_banner.setFixedWidth(400)
        root.addWidget(
            self._alert_banner,
            0,
            Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignHCenter,
        )
        self._alert_banner.hide()

        self._status_lbl = QLabel("Status: Pronto")
        self._status_lbl.setStyleSheet(f"color: {COLORS['text_dim']}; font-size: 11px;")
        root.addWidget(self._status_lbl)

    def _log_event(self, msg: str, color: str = COLORS["text"]):
        ts = datetime.now().strftime("%H:%M:%S")
        self.op_tab.log_edit.append(
            f'<span style="color:{COLORS["text_dim"]}">[{ts}]</span> '
            f'<span style="color:{color}">{msg}</span>'
        )
        cursor = self.op_tab.log_edit.textCursor()
        if self.op_tab.log_edit.document().blockCount() > 500:
            cursor.movePosition(cursor.MoveOperation.Start)
            # Seleciona e remove a primeira linha (bloco) de forma atômica
            cursor.movePosition(
                cursor.MoveOperation.NextBlock, cursor.MoveMode.KeepAnchor
            )
            cursor.removeSelectedText()
            # Garante que o auto-scroll continue funcionando
            self.op_tab.log_edit.moveCursor(cursor.MoveOperation.End)

    def _on_flow_batch_ready(self, top_50: list, total_active: int, total_attacks: int):
        """Recebe o pacote completo processado pelo Orchestrator. Paint puro sem estado O(M) de cache local."""
        self._table.setRowCount(len(top_50))
        n_count = a_count = 0

        for row, res in enumerate(top_50):
            label = res.label

            if label == "ATTACK":
                col = COLORS["danger"]
                display_label = "🚨 ATAQUE"
                a_count += 1
            elif label == "SUSPICIOUS":
                col = COLORS["warning"]
                display_label = "⚠️ POSSÍVEL ATAQUE"
                n_count += 1
            elif label == "ERROR":
                col = COLORS["danger"]
                display_label = "❌ ERRO IA"
                n_count += 1
            else:
                col = COLORS["success"]
                display_label = "✅ Normal"
                n_count += 1

            self._table.setItem(row, 0, QTableWidgetItem(res.time))
            self._table.setItem(row, 1, QTableWidgetItem(res.flow_key))
            self._table.setItem(row, 2, QTableWidgetItem(res.proto))
            self._table.setItem(row, 3, QTableWidgetItem(str(res.pkts)))
            self._table.setItem(row, 4, QTableWidgetItem(f"{res.duration:.1f}s"))

            s_item = QTableWidgetItem(display_label)
            s_item.setForeground(QBrush(QColor(col)))
            s_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            self._table.setItem(row, 5, s_item)
            self._table.setItem(row, 6, QTableWidgetItem(f"{res.confidence:.1%}"))

        self._card_total.update_value(total_active)
        # Nota: O contador 'total_attacks' inclui apenas "ATTACK" confirmados.
        # Categoria "SUSPICIOUS" continua computando visualmente como Normal na estatística do card principal.
        self._card_normal.update_value(total_active - total_attacks)
        self._card_attack.update_value(total_attacks)
        self._chart.push(n_count, a_count)

    def _on_attack_started(self, src_ip: str, label: str):
        """Slot unificado acionado quando o motor confirma um ataque."""
        ts = datetime.now().strftime("%H:%M:%S")
        self._log_event(f"🚨 {label}: Tráfego suspeito de {src_ip}", COLORS["danger"])
        self._alert_banner.show_alert(f"{label}: IP {src_ip}")
        self._notify_attack(src_ip, label)

        # Histórico (Unificado: usado para Exportação de Logs)
        self._attack_history.append([ts, src_ip, label, "Confirmado"])

    def _on_attack_normalized(self, data: dict):
        """Slot para tratar o fim de um ataque (Sinal dedicado)."""
        src_ip = data.get("src_ip")
        self._alert_banner.hide_alert()
        self._log_event(
            f"✅ Normalizado: Tráfego suspeito de {src_ip} cessou.", COLORS["success"]
        )

    def _notify_attack(self, ip, label):
        now = datetime.now().timestamp()
        last_notify = self._notified_ips.get(ip, 0)
        if now - last_notify > 60:
            self._notified_ips[ip] = now
            if hasattr(self, "_tray") and self._tray:
                self._tray.showMessage(
                    f"🛡 {label}",
                    f"Anomalia em {ip}",
                    QSystemTrayIcon.MessageIcon.Warning,
                )

    def _on_pps_updated(self, pps: float):
        self._card_pkts.update_value(f"{pps:,.0f}")

    def _on_status(self, msg: str):
        self._status_lbl.setText(f"Status: {msg}")
        self._log_event(f"ℹ️ {msg}", COLORS["text_dim"])

    def _on_error(self, err: str):
        self._log_event(f"❌ ERRO: {err}", COLORS["danger"])
        QMessageBox.critical(self, "Erro", err)

    def _on_block_requested(self, ip: str, pps: float):
        self._alert_banner.show_alert(
            f"⛔ BLOQUEANDO O TRAFEGO: {ip} ({pps:.0f} pps)", duration_ms=4000
        )
        if hasattr(self, "_tray") and self._tray:
            self._tray.showMessage(
                "🛡 Bloqueio",
                f"IP {ip} enviado para o Firewall.",
                QSystemTrayIcon.MessageIcon.Warning,
            )

    def _on_ip_blocked(self, ip: str, pps: float, ts: str):
        self._log_event(f"🚨 BLOQUEADO: {ip} ({pps:.0f} PPS)", COLORS["danger"])

    def _on_ip_unblocked(self, ip: str):
        self._log_event(f"🔓 DESBLOQUEADO: {ip}", COLORS["success"])

    def _on_state_sync(self, blocked_ips: dict):
        self._refresh_blocked_table(blocked_ips)
        self._update_blocked_tab_title(len(blocked_ips))

    def _update_blocked_tab_title(self, cnt: int = 0):
        self._tabs.setTabText(
            2, f"🔒 BLOQUEADOS ({cnt})" if cnt > 0 else "🔒 BLOQUEADOS"
        )

    def _on_whitelist_changed(self, items: list):
        self.wl_tab.wl_list.clear()
        self.wl_tab.wl_list.addItems(items)

    def _refresh_ui(self):
        """Apenas atualiza o timer (A UI principal é movida pelo evento flow_batch_ready)"""
        elapsed = datetime.now() - self._start_time
        h, rem = divmod(int(elapsed.total_seconds()), 3600)
        m, s = divmod(rem, 60)
        self._clock_lbl.setText(
            f"{datetime.now().strftime('%H:%M:%S')} | Uptime: {h:02d}:{m:02d}:{s:02d}"
        )

    def _start_monitor(self):
        iface = self.cfg_tab.iface_combo.currentData()

        # Salva a interface escolhida
        cfg = load_config()
        cfg["interface"] = iface
        save_config(cfg)

        if self._engine.start(iface):
            self.op_tab.start_btn.setEnabled(False)
            self.op_tab.stop_btn.setEnabled(True)
            self.cfg_tab.iface_combo.setEnabled(False)
            self._start_time = datetime.now()
            self._log_event("🚀 Proteção iniciada.", COLORS["success"])
        else:
            self._log_event("⚠️ Falha ao iniciar. Verifique os logs.", COLORS["danger"])

    def _stop_monitor(self):
        self._engine.stop()
        self.op_tab.start_btn.setEnabled(True)
        self.op_tab.stop_btn.setEnabled(False)
        self.cfg_tab.iface_combo.setEnabled(True)
        self._alert_banner.hide_alert()
        self._log_event("⏹ Proteção interrompida.", COLORS["warning"])

    def _on_threshold_changed(self, p_id: str, val: int, lbl):
        f_val = val / 100.0
        lbl.setText(f"{f_val:.2f}")
        self._engine.set_ai_threshold(p_id, f_val)
        self._save_current_settings()

    def _reset_ai_thresholds(self):
        defaults = {"home": -0.30, "pme": -0.15, "datacenter": 0.00}
        for p_id, val in defaults.items():
            self._engine.set_ai_threshold(p_id, val)
            slider, lbl = self.cfg_tab.ai_controls[p_id]
            slider.setValue(int(val * 100))
            lbl.setText(f"{val:.2f}")
        self._log_event("🔄 Thresholds de IA redefinidos.", COLORS["accent"])
        self._save_current_settings()

    def _toggle_autoblock(self, st: int):
        enabled = st != Qt.CheckState.Unchecked.value
        self._engine.set_autoblock(enabled)
        self._log_event(
            f"🛡 Bloqueio automático: {'LIGADO' if enabled else 'DESLIGADO'}"
        )
        self._save_current_settings()

    def _change_profile(self, index: int):
        p = self.cfg_tab.profile_combo.itemData(index)
        self._engine.set_profile(p)
        self._log_event(f"🧠 Perfil IA: {p.upper()}")
        self._save_current_settings()

    def _add_to_whitelist(self):
        ip = self.wl_tab.wl_input.text().strip()
        if ip and self._engine.add_to_whitelist(ip):
            self.wl_tab.wl_list.addItem(ip)
            self.wl_tab.wl_input.clear()
            self._log_event(f"✅ Whitelist: {ip}")
        elif ip:
            self._log_event(f"⚠️ IP/Rede inválido: {ip}", COLORS["warning"])

    def _remove_from_whitelist(self):
        item = self.wl_tab.wl_list.currentItem()
        if item:
            ip = item.text()
            self._engine.remove_from_whitelist(ip)
            self.wl_tab.wl_list.takeItem(self.wl_tab.wl_list.row(item))
            self._log_event(f"🗑 Whitelist removido: {ip}")

    def _clear_whitelist(self):
        if self.wl_tab.wl_list.count() == 0:
            return

        reply = QMessageBox.question(
            self,
            "Limpar Whitelist",
            "Deseja remover TODOS os IPs da Whitelist?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._engine.clear_whitelist()
            self._log_event("🗑 Whitelist totalmente limpa.", COLORS["warning"])

    def _refresh_blocked_table(self, blocked_ips: dict = None):
        t = self.blocked_tab.table
        t.setRowCount(0)

        if blocked_ips is None:
            blocked_ips = self._engine.get_blocked_ips()

        cnt = len(blocked_ips)
        self._update_blocked_tab_title(cnt)

        for row, (ip, info) in enumerate(blocked_ips.items()):
            t.insertRow(row)
            it = QTableWidgetItem(ip)
            it.setForeground(QBrush(QColor(COLORS["danger"])))
            t.setItem(row, 0, it)
            t.setItem(row, 1, QTableWidgetItem(info.get("time", "--:--:--")))
            t.setItem(row, 2, QTableWidgetItem(f"{info.get('pps', 0):.0f} PPS"))
            btn = QPushButton("🔓")
            btn.setFixedWidth(40)
            btn.setStyleSheet(
                f"color: {COLORS['warning']}; border: 1px solid {COLORS['warning']}; background: transparent;"
            )
            btn.clicked.connect(lambda chk, i=ip: self._unblock_ip(i))
            t.setCellWidget(row, 3, btn)

    def _unblock_ip(self, ip: str):
        self._engine.unblock_ip(ip)

    def _save_settings(self):
        self._save_current_settings()
        self._log_event("💾 Configurações aplicadas com sucesso.", COLORS["success"])
        QMessageBox.information(
            self, "Sucesso", "As configurações de rede e IA foram aplicadas."
        )

    def _save_current_settings(self):
        # FIX #5: usa getter público em vez de acessar atributos privados do engine
        cfg = self._engine.get_config_snapshot()
        cfg["interface"] = self.cfg_tab.iface_combo.currentData()
        save_config(cfg)

    def _load_settings_to_engine(self):
        self._engine.set_profile(self._config["profile"])
        self._engine.set_autoblock(self._config["autoblock"])
        for p_id, val in self._config["ai_thresholds"].items():
            self._engine.set_ai_threshold(p_id, val)

    def _apply_settings_to_ui(self):
        cfg = self._config

        # Profile
        idx = self.cfg_tab.profile_combo.findData(cfg["profile"])
        if idx >= 0:
            self.cfg_tab.profile_combo.setCurrentIndex(idx)

        # Autoblock
        self.cfg_tab.autoblock_chk.setChecked(cfg["autoblock"])

        # Thresholds
        for p_id, val in cfg["ai_thresholds"].items():
            if p_id in self.cfg_tab.ai_controls:
                slider, lbl = self.cfg_tab.ai_controls[p_id]
                slider.setValue(int(val * 100))
                lbl.setText(f"{val:.2f}")

        # Interface
        if cfg["interface"]:
            idx = self.cfg_tab.iface_combo.findData(cfg["interface"])
            if idx >= 0:
                self.cfg_tab.iface_combo.setCurrentIndex(idx)

    def _unblock_all(self):
        self._engine.unblock_all()
        self._log_event("🔓 Firewall limpo.", COLORS["warning"])

    def _auto_start_monitoring(self):
        """Tenta iniciar o monitoramento automaticamente se houver interface salva."""
        iface = self.cfg_tab.iface_combo.currentData()
        if iface:
            self.logger.info(f"Auto-start acionado para interface: {iface}")
            self._start_monitor()

    def _export_log(self):
        if len(self._attack_history) == 0:
            QMessageBox.information(
                self, "Exportar", "Não há eventos de ataque registrados."
            )
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Exportar Relatório Histórico", "ddos_logs.csv", "CSV (*.csv)"
        )
        if path:
            try:
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Hora", "Fluxo", "Tipo", "Nível de Ameaça"])
                    writer.writerows(self._attack_history)
                self._log_event(
                    f"📊 Relatório histórico salvo: {path}", COLORS["success"]
                )
            except Exception as e:
                self._log_event(f"❌ Erro ao exportar: {e}", COLORS["danger"])

    def _clear_log(self):
        self.op_tab.log_edit.clear()
        self._attack_history.clear()

    def _populate_ifaces(self, combo):
        combo.clear()
        combo.addItem("Procurando interfaces...", None)
        combo.setEnabled(False)
        self._scapy_thread = ScapyLoaderThread(self)
        self._scapy_thread.finished.connect(
            lambda res, default: self._on_scapy_loaded(combo, res, default)
        )
        self._scapy_thread.start()

    def _on_scapy_loaded(self, combo, res, default_name):
        combo.clear()
        combo.setEnabled(True)
        if not res:
            combo.addItem("Adaptador Padrão", None)
            return

        for desc, name in res:
            combo.addItem(desc, name)

        idx = combo.findData(default_name)
        if idx >= 0:
            combo.setCurrentIndex(idx)

    def _setup_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            self._tray = None
            return

        self._tray = QSystemTrayIcon(self)

        # Tenta carregar ícone do arquivo; fallback para ícone desenhado
        icon_path = os.path.join(_ROOT, "assets", "icon.png")
        if os.path.exists(icon_path):
            tray_icon = QIcon(icon_path)
        else:
            p = QPixmap(32, 32)
            p.fill(Qt.GlobalColor.transparent)
            ptr = QPainter(p)
            ptr.setBrush(QBrush(QColor(COLORS["accent"])))
            ptr.drawEllipse(4, 4, 24, 24)
            ptr.end()
            tray_icon = QIcon(p)

        self._tray.setIcon(tray_icon)
        self._tray.setToolTip("Forest Sentinel — Em execução")

        # Menu de contexto do tray
        tray_menu = QMenu()
        tray_menu.setStyleSheet(
            f"""
            QMenu {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                padding: 4px;
            }}
            QMenu::item {{
                padding: 6px 20px;
                border-radius: 4px;
            }}
            QMenu::item:selected {{
                background-color: {COLORS['accent']};
                color: #ffffff;
            }}
            """
        )

        act_restore = QAction("🖥  Restaurar Janela", self)
        act_restore.triggered.connect(self._tray_restore)
        tray_menu.addAction(act_restore)

        tray_menu.addSeparator()

        act_quit = QAction("✖  Encerrar Monitor", self)
        act_quit.triggered.connect(self._tray_quit)
        tray_menu.addAction(act_quit)

        self._tray.setContextMenu(tray_menu)

        # Duplo clique restaura a janela
        self._tray.activated.connect(self._on_tray_activated)

        self._tray.show()

    def _on_tray_activated(self, reason):
        """Restaura a janela ao dar duplo clique no ícone do tray."""
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self._tray_restore()

    def _tray_restore(self):
        """Restaura a janela principal maximizada a partir do tray."""
        self.showMaximized()
        self.activateWindow()
        self.raise_()

    def _tray_quit(self):
        """Encerra o aplicativo completamente a partir do menu do tray."""
        self._engine.stop()
        QApplication.quit()

    def closeEvent(self, event):
        """Intercepta o fechamento da janela: minimiza para o tray em vez de fechar."""
        if self._tray and self._tray.isVisible():
            event.ignore()
            self.hide()
        else:
            # Sem tray disponível — fecha normalmente
            self._engine.stop()
            event.accept()

    def changeEvent(self, event):
        """Intercepta a minimização da janela: envia para o tray em vez da barra de tarefas."""
        super().changeEvent(event)
        if event.type() == QEvent.Type.WindowStateChange:
            if self.isMinimized() and self._tray and self._tray.isVisible():
                # Adiamos o hide() para após o loop de eventos processar a mudança
                # de estado. Chamar hide() diretamente aqui é instável no Qt.
                QTimer.singleShot(0, self._minimize_to_tray)

    def _minimize_to_tray(self):
        """Oculta a janela e envia para o tray sem notificação."""
        self.hide()

    def _warn_non_admin(self):
        QMessageBox.warning(
            self,
            "Aviso",
            "Execute como Administrador para habilitar captura de pacotes e firewall.",
        )
