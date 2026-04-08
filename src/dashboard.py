"""
dashboard.py
------------
Interface principal do Forest Sentinel.
"""

import sys
import os
import logging
import collections
import time
import csv
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
from PyQt6.QtGui import QColor, QFont, QBrush, QIcon, QPixmap, QPainter, QAction, QTextCursor

# Local Modules
import i18n
from i18n import tr
from utils import (
    get_root_dir,
    get_timestamp,
    RES_ICON,
    RES_LOGO,
    RES_FLAG_BR,
    RES_FLAG_US,
    is_admin,
    format_flow_key,
)
from constants import DetectionStatus, FlowResult
from ui_components import (
    COLORS,
    MetricCard,
    ActivityChart,
    AlertBanner,
    QSS_BUTTON,
    QSS_INPUT
)
from ui_tabs import OperationTab, ConfigurationTab, BlockedTab, WhitelistTab
from monitor_engine import MonitorEngine
from config_manager import load_config, save_config

_ROOT = get_root_dir()


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


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Forest Sentinel")
        self.setMinimumSize(1280, 800)

        # Configuração do Ícone da Janela
        self.setWindowIcon(QIcon(RES_ICON))

        self._apply_global_style()

        self.logger = logging.getLogger("UI")

        self._start_time = datetime.now()
        self._attack_history = collections.deque(maxlen=500)
        self._notify_ips: dict[str, float] = {}  # Throttle de notificações do tray por IP
        self._tray_notified = False  # Avisa "rodando no tray" apenas 1x por sessão
        self._tray = None
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
        self._update_block_tab_count()
        self._log_event(tr("msg_loaded"), COLORS["text_dim"])

        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._refresh_ui)
        self._refresh_timer.start(1000)

        if not is_admin():
            QTimer.singleShot(1500, self._warn_non_admin)

        # 🚀 AUTO-START: Monitoramento automático movido para _on_scapy_loaded 
        # (Garante que a interface já foi carregada do hardware)

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

        # Header Logo e Título
        logo_lbl = QLabel()
        logo_pix = QPixmap(RES_LOGO).scaled(
            48, 48, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation
        )
        logo_lbl.setPixmap(logo_pix)
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

        # Botões de Idioma
        lang_row = QHBoxLayout()
        lang_row.addStretch()

        flag_btn_style = f"""
            QPushButton {{
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                background-color: {COLORS['bg_card']};
                padding: 2px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['border']};
            }}
            QPushButton:pressed {{
                background-color: {COLORS['accent']};
            }}
        """

        self.btn_pt = QPushButton()
        self.btn_pt.setIcon(QIcon(RES_FLAG_BR))
        self.btn_pt.setFixedSize(36, 26)
        self.btn_pt.setStyleSheet(flag_btn_style)
        self.btn_pt.clicked.connect(lambda: self._change_lang("pt"))

        self.btn_en = QPushButton()
        self.btn_en.setIcon(QIcon(RES_FLAG_US))
        self.btn_en.setFixedSize(36, 26)
        self.btn_en.setStyleSheet(flag_btn_style)
        self.btn_en.clicked.connect(lambda: self._change_lang("en"))
        
        header.addWidget(self.btn_pt)
        header.addWidget(self.btn_en)

        self._clock_lbl = QLabel("--:--:--")
        self._clock_lbl.setStyleSheet(f"color: {COLORS['text_dim']}; font-size: 12px;")
        header.addWidget(self._clock_lbl)
        root.addLayout(header)

        m_row = QHBoxLayout()
        m_row.setSpacing(10)
        self._card_total = MetricCard(tr("card_active"), "0", tr("unit_flows"), COLORS["accent"])
        self._card_normal = MetricCard(tr("card_normal"), "0", tr("unit_flows"), COLORS["success"])
        self._card_attack = MetricCard(tr("card_attacks"), "0", tr("unit_alerts"), COLORS["danger"])
        self._card_pkts = MetricCard(tr("card_traffic"), "0", tr("unit_pps"), COLORS["warning"])
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
        self._table.setHorizontalHeaderLabels(self._table_headers())
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

        self._tabs.addTab(self.op_tab, tr("tab_monitor"))
        self._tabs.addTab(self.cfg_tab, tr("tab_config"))
        self._tabs.addTab(self.blocked_tab, tr("tab_blocked"))
        self._tabs.addTab(self.wl_tab, tr("tab_whitelist"))

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

        self._status_lbl = QLabel(tr("status_ready"))
        self._status_lbl.setStyleSheet(f"color: {COLORS['text_dim']}; font-size: 11px;")
        root.addWidget(self._status_lbl)

    def _change_lang(self, lang: str):
        i18n.set_lang(lang)
        self._apply_language()

    def _apply_language(self):
        """Reaplica todos os textos traduzíveis da UI sem reconstruir widgets."""
        # Abas
        self._tabs.setTabText(0, tr("tab_monitor"))
        self._tabs.setTabText(1, tr("tab_config"))
        self._update_block_tab_count()
        self._tabs.setTabText(3, tr("tab_whitelist"))

        # Cabeçalhos da tabela
        self._table.setHorizontalHeaderLabels(self._table_headers())

        # Cards de métrica
        self._card_total.title_lbl.setText(tr("card_active"))
        self._card_total.unit_lbl.setText(tr("unit_flows"))
        self._card_normal.title_lbl.setText(tr("card_normal"))
        self._card_normal.unit_lbl.setText(tr("unit_flows"))
        self._card_attack.title_lbl.setText(tr("card_attacks"))
        self._card_attack.unit_lbl.setText(tr("unit_alerts"))
        self._card_pkts.title_lbl.setText(tr("card_traffic"))
        self._card_pkts.unit_lbl.setText(tr("unit_pps"))

        # Status bar
        self._status_lbl.setText(tr("status_ready"))

        # Tray
        if self._tray:
            self._tray.setToolTip(tr("tray_tooltip"))
            menu = self._tray.contextMenu()
            if menu:
                actions = menu.actions()
                if len(actions) >= 1:
                    actions[0].setText(tr("tray_restore"))
                if len(actions) >= 3:
                    actions[2].setText(tr("tray_quit"))

        # Gráfico
        self._chart.apply_language()

        # Sub-abas
        self.op_tab.apply_language()
        self.cfg_tab.apply_language()
        self.blocked_tab.apply_language()
        self.wl_tab.apply_language()

    def _table_headers(self) -> list[str]:
        return [
            tr("col_time"), tr("col_flow"), tr("col_proto"),
            tr("col_pkts"), tr("col_duration"), tr("col_status"), tr("col_threat"),
        ]

    # ── Slots de eventos ───────────────────────────────────────────────────

    def _log_event(self, msg: str, color=None):
        ts = get_timestamp()
        color = color or COLORS["text_dim"]
        # 🚀 Revertido para QTextEdit: Suporta HTML <span> nativamente.
        # A poda manual é necessária pois QTextEdit não tem setMaximumBlockCount.
        self.op_tab.log_edit.append(
            f'<span style="color:{COLORS["text_dim"]}">[{ts}]</span> '
            f'<span style="color:{color}">{msg}</span>'
        )
        
        doc = self.op_tab.log_edit.document()
        if doc.blockCount() > 500:
            cursor = self.op_tab.log_edit.textCursor()
            cursor.movePosition(cursor.MoveOperation.Start)
            cursor.select(cursor.SelectionType.BlockUnderCursor)
            cursor.removeSelectedText()
            cursor.deleteChar() # Remove o line break residual


    def _on_flow_batch_ready(self, top_50: list, total_active: int, total_attacks: int):
        """Recebe o pacote completo processado pelo Orchestrator. Paint puro otimizado."""
        current_rows = self._table.rowCount()
        new_rows = len(top_50)
        
        if current_rows != new_rows:
            self._table.setRowCount(new_rows)
            
        n_count = a_count = 0

        for row, res in enumerate(top_50):
            label = res.label

            if label == DetectionStatus.ATTACK.name:
                col = COLORS["danger"]
                display_label = tr("label_attack")
                a_count += 1
            elif label == DetectionStatus.SUSPICIOUS.name:
                col = COLORS["warning"]
                display_label = tr("label_suspicious")
                n_count += 1
            elif label == DetectionStatus.ERROR.name:
                col = COLORS["danger"]
                display_label = tr("label_error")
                n_count += 1
            else:
                col = COLORS["success"]
                display_label = tr("label_normal")
                n_count += 1

            # Reaproveita itens existentes para evitar overhead de GC e cintilação
            self._set_table_text(row, 0, res.time)
            self._set_table_text(row, 1, res.flow_key)
            self._set_table_text(row, 2, res.proto)
            self._set_table_text(row, 3, str(res.pkts))
            self._set_table_text(row, 4, f"{res.duration:.1f}s")

            # Coluna de Status (Destaque visual)
            s_item = self._table.item(row, 5)
            if not s_item:
                s_item = QTableWidgetItem()
                s_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
                self._table.setItem(row, 5, s_item)
            
            if s_item.text() != display_label:
                s_item.setText(display_label)
                s_item.setForeground(QBrush(QColor(col)))

            self._set_table_text(row, 6, f"{res.confidence:.1%}")

        self._card_total.update_value(total_active)
        self._card_normal.update_value(total_active - total_attacks)
        self._card_attack.update_value(total_attacks)
        self._chart.push(n_count, a_count)

    def _set_table_text(self, row, col, text):
        it = self._table.item(row, col)
        if it:
            if it.text() != str(text):
                it.setText(str(text))
        else:
            self._table.setItem(row, col, QTableWidgetItem(str(text)))

    def _on_attack_started(self, ip: str, label: str):
        """Slot unificado: Loga o evento, atualiza UI e gerencia notificações no tray."""
        ts = datetime.now().strftime("%H:%M:%S")
        
        # 1. Atualizar UI e Log
        self._log_event(tr("log_attack_traffic", label=label, ip=ip), COLORS["danger"])
        self._alert_banner.show_alert(f"{label}: IP {ip}")
        self._attack_history.append([ts, ip, label, "Confirmado"])

        # 2. Notificação no Tray (com Throttle para não saturar o Windows)
        now = time.time()
        last_notify = self._notify_ips.get(ip, 0)
        if now - last_notify > 60:
            self._notify_ips[ip] = now
            if self._tray:
                self._tray.showMessage(
                    f"🛡 {label}",
                    tr("log_attack_tray", ip=ip),
                    QSystemTrayIcon.MessageIcon.Warning,
                    3000,
                )

    def _on_attack_normalized(self, data: dict):
        """Slot para tratar o fim de um ataque (Sinal dedicado)."""
        src_ip = data.get("src_ip")
        self._alert_banner.hide_alert()
        self._log_event(tr("log_normalized", ip=src_ip), COLORS["success"])

    def _on_pps_updated(self, pps: float):
        self._card_pkts.update_value(f"{pps:,.0f}")

    def _on_status(self, msg: str):
        self._status_lbl.setText(tr("log_status_prefix", msg=msg))
        self._log_event(tr("log_status_event", msg=msg), COLORS["text_dim"])

    def _on_error(self, err: str):
        self._log_event(tr("log_error", err=err), COLORS["danger"])
        QMessageBox.critical(self, "Erro", err)

    def _on_block_requested(self, ip: str, pps: float):
        self._alert_banner.show_alert(
            tr("log_blocking_req", ip=ip, pps=pps), duration_ms=4000
        )
        if self._tray:
            self._tray.showMessage(
                tr("log_block_tray_t"),
                tr("log_block_tray", ip=ip),
                QSystemTrayIcon.MessageIcon.Warning,
                4000,
            )

    def _on_ip_blocked(self, ip: str, pps: float, ts: str):
        self._log_event(tr("log_blocked", ip=ip, pps=pps), COLORS["danger"])
        self._update_block_tab_count()

    def _on_ip_unblocked(self, ip: str):
        self._log_event(tr("log_unblocked", ip=ip), COLORS["success"])
        self._update_block_tab_count()

    def _on_state_sync(self, blocked_ips: dict):
        # _refresh_blocked_table já chama _update_blocked_tab_title internamente
        self._refresh_blocked_table(blocked_ips)

    def _update_block_tab_count(self):
        count = len(self._engine.get_blocked_ips())
        if count > 0:
            self._tabs.setTabText(2, tr("tab_blocked_cnt", n=count))
        else:
            self._tabs.setTabText(2, tr("tab_blocked"))

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

        # Otimização: Não salvamos config desnecessariamente ao iniciar
        if self._engine.start(iface):
            self.op_tab.start_btn.setEnabled(False)
            self.op_tab.stop_btn.setEnabled(True)
            self.cfg_tab.iface_combo.setEnabled(False)
            self._start_time = datetime.now()
            self._log_event(tr("msg_started"), COLORS["success"])
        else:
            self._log_event(tr("msg_start_fail"), COLORS["danger"])

    def _stop_monitor(self):
        self._engine.stop()
        self.op_tab.start_btn.setEnabled(True)
        self.op_tab.stop_btn.setEnabled(False)
        self.cfg_tab.iface_combo.setEnabled(True)
        self._alert_banner.hide_alert()
        self._log_event(tr("msg_stopped"), COLORS["warning"])

    def _on_threshold_changed(self, p_id: str, val: int, lbl):
        f_val = val / 100.0
        lbl.setText(f"{f_val:.2f}")
        self._engine.set_ai_threshold(p_id, f_val)
        # Otimização: Removido save_current_settings por motivo de latência de UI (Save apenas com botão Apply)

    def _reset_ai_thresholds(self):
        defaults = {"home": -0.30, "pme": -0.15, "datacenter": 0.00}
        for p_id, val in defaults.items():
            self._engine.set_ai_threshold(p_id, val)
            slider, lbl = self.cfg_tab.ai_controls[p_id]
            slider.setValue(int(val * 100))
            lbl.setText(f"{val:.2f}")
        self._log_event(tr("msg_thresholds_reset"), COLORS["accent"])
        # Otimização: Removido save_current_settings redundante

    def _toggle_autoblock(self, st: int):
        enabled = st != Qt.CheckState.Unchecked.value
        self._engine.set_autoblock(enabled)
        self._log_event(tr("msg_autoblock_on") if enabled else tr("msg_autoblock_off"))
        # Otimização: Removido save_current_settings redundante

    def _change_profile(self, index: int):
        p = self.cfg_tab.profile_combo.itemData(index)
        self._engine.set_profile(p)
        self._log_event(tr("msg_profile", p=p.upper()))
        # Otimização: Removido save_current_settings redundante

    def _add_to_whitelist(self):
        ip = self.wl_tab.wl_input.text().strip()
        if ip and self._engine.add_to_whitelist(ip):
            self.wl_tab.wl_list.addItem(ip)
            self.wl_tab.wl_input.clear()
            self._log_event(tr("msg_wl_added", ip=ip))
        elif ip:
            self._log_event(tr("msg_wl_invalid", ip=ip), COLORS["warning"])

    def _remove_from_whitelist(self):
        item = self.wl_tab.wl_list.currentItem()
        if item:
            ip = item.text()
            self._engine.remove_from_whitelist(ip)
            self.wl_tab.wl_list.takeItem(self.wl_tab.wl_list.row(item))
            self._log_event(tr("msg_wl_removed", ip=ip))

    def _clear_whitelist(self):
        if self.wl_tab.wl_list.count() == 0:
            return

        reply = QMessageBox.question(
            self,
            tr("msg_wl_clear_title"),
            tr("msg_wl_clear_q"),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._engine.clear_whitelist()
            self._log_event(tr("msg_wl_cleared"), COLORS["warning"])

    def _refresh_blocked_table(self, blocked_ips: dict = None):
        t = self.blocked_tab.table

        if blocked_ips is None:
            blocked_ips = self._engine.get_blocked_ips()

        self._update_block_tab_count()

        # Otimização in-place para evitar limpar/recriar elementos QTableWidgetItem e QPushButton
        current_rows = t.rowCount()
        new_rows = len(blocked_ips)
        if current_rows != new_rows:
            t.setRowCount(new_rows)

        for row, (ip, info) in enumerate(blocked_ips.items()):
            # IP
            it_ip = t.item(row, 0)
            if not it_ip:
                it_ip = QTableWidgetItem()
                it_ip.setForeground(QBrush(QColor(COLORS["danger"])))
                t.setItem(row, 0, it_ip)
            if it_ip.text() != ip:
                it_ip.setText(ip)

            # Time
            time_str = info.get("time", "--:--:--")
            it_time = t.item(row, 1)
            if not it_time:
                it_time = QTableWidgetItem()
                t.setItem(row, 1, it_time)
            if it_time.text() != time_str:
                it_time.setText(time_str)

            # PPS
            pps_str = f"{info.get('pps', 0):.0f} PPS"
            it_pps = t.item(row, 2)
            if not it_pps:
                it_pps = QTableWidgetItem()
                t.setItem(row, 2, it_pps)
            if it_pps.text() != pps_str:
                it_pps.setText(pps_str)

            # Botão Unblock (reaproveitar e apenas atualizar a prop 'ip')
            btn = t.cellWidget(row, 3)
            if not btn:
                btn = QPushButton("🔓")
                btn.setStyleSheet(QSS_BUTTON(COLORS["success"]) + "padding: 2px;")
                btn.setFixedWidth(40)
                btn.clicked.connect(self._handle_unblock_click)
                t.setCellWidget(row, 3, btn)
            btn.setProperty("target_ip", ip)

    def _handle_unblock_click(self):
        btn = self.sender()
        if btn:
            ip = btn.property("target_ip")
            if ip:
                self._engine.unblock_ip(ip)

    def _save_settings(self):
        self._save_current_settings()
        self._log_event(tr("msg_settings_saved"), COLORS["success"])
        QMessageBox.information(
            self, tr("msg_settings_title"), tr("msg_settings_ok")
        )

    def _save_current_settings(self):
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
        self._log_event(tr("msg_fw_cleared"), COLORS["warning"])

    def _auto_start_monitoring(self):
        """Tenta iniciar o monitoramento automaticamente se houver interface salva."""
        iface = self.cfg_tab.iface_combo.currentData()
        if iface:
            self.logger.info(f"Auto-start acionado para interface: {iface}")
            self._start_monitor()

    def _export_log(self):
        if len(self._attack_history) == 0:
            QMessageBox.information(
                self, tr("msg_export_title"), tr("msg_no_attacks")
            )
            return

        path, _ = QFileDialog.getSaveFileName(
            self, tr("msg_export_dlg"), "ddos_logs.csv", "CSV (*.csv)"
        )
        if path:
            try:
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        tr("col_time"), tr("col_flow"), "Tipo", tr("col_threat")
                    ])
                    writer.writerows(self._attack_history)
                self._log_event(tr("msg_export_saved", path=path), COLORS["success"])
            except Exception as e:
                self._log_event(tr("msg_export_err", e=e), COLORS["danger"])

    def _clear_log(self):
        self.op_tab.log_edit.clear()
        self._attack_history.clear()

    def _populate_ifaces(self, combo):
        combo.clear()
        combo.addItem(tr("msg_if_autostart"), None)
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
            combo.addItem(tr("msg_if_default"), None)
            return

        for desc, name in res:
            combo.addItem(desc, name)

        # 1. Prioriza a interface que o usuário salvou no config
        saved_iface = self._config.get("interface")
        idx = combo.findData(saved_iface) if saved_iface else -1

        # 2. Se não houver salva (ou for inválida), usa a padrão detectada pelo Scapy
        if idx < 0:
            idx = combo.findData(default_name)

        if idx >= 0:
            combo.setCurrentIndex(idx)

        # 3. 🚀 Início automático agora é SEGURO: a UI já possui os dados carregados
        if self._config.get("autostart", True):
            self._auto_start_monitoring()

    def _setup_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return

        self._tray = QSystemTrayIcon(QIcon(RES_ICON), self)
        self._tray.setToolTip(tr("tray_tooltip"))

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

        act_restore = QAction(tr("tray_restore"), self)
        act_restore.triggered.connect(self._tray_restore)
        tray_menu.addAction(act_restore)

        tray_menu.addSeparator()

        act_quit = QAction(tr("tray_quit"), self)
        act_quit.triggered.connect(self._tray_quit)
        tray_menu.addAction(act_quit)

        self._tray.setContextMenu(tray_menu)
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
            self._notify_tray_once()
        else:
            # Sem tray disponível — fecha normalmente
            self._engine.stop()
            event.accept()

    def _notify_tray_once(self):
        """Exibe o balão do tray informando que o app continua rodando — apenas 1x por sessão."""
        if self._tray_notified or not self._tray:
            return
        self._tray_notified = True
        self._tray.showMessage(
            tr("tray_bg_title"),
            tr("tray_bg_msg"),
            QSystemTrayIcon.MessageIcon.Information,
            4000,
        )

    def changeEvent(self, event):
        """Intercepta a minimização da janela: envia para o tray em vez da barra de tarefas."""
        super().changeEvent(event)
        if event.type() == QEvent.Type.WindowStateChange:
            if self.isMinimized() and self._tray and self._tray.isVisible():
                QTimer.singleShot(0, self._minimize_to_tray)

    def _minimize_to_tray(self):
        """Oculta a janela e envia para o tray, avisando apenas na primeira vez."""
        self.hide()
        self._notify_tray_once()

    def _warn_non_admin(self):
        QMessageBox.warning(
            self,
            tr("msg_admin_title"),
            tr("msg_admin_warn"),
        )
