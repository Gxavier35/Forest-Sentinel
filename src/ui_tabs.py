from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QGroupBox,
    QPushButton,
    QTableWidget,
    QHeaderView,
    QTextEdit,
    QComboBox,
    QCheckBox,
    QSlider,
    QLineEdit,
    QListWidget,
)
from PyQt6.QtCore import Qt
from ui_components import (
    COLORS,
    QSS_GROUPBOX,
    QSS_BUTTON,
    QSS_INPUT,
    QSS_LIST,
    QSS_COMBO
)
from config_manager import DEFAULT_CONFIG
from i18n import tr


class BaseTab(QWidget):
    """Classe base para fornecer estilos comuns a todas as abas."""

    def __init__(self, engine, parent=None):
        super().__init__(parent)
        self.engine = engine

    def apply_language(self):
        """Subclasses devem sobrescrever para atualizar seus textos."""
        pass


class OperationTab(BaseTab):
    def __init__(self, engine, parent=None):
        super().__init__(engine, parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(10, 10, 10, 10)
        self._layout.setSpacing(10)

        self.op_group = QGroupBox(tr("op_group"))
        self.op_group.setStyleSheet(QSS_GROUPBOX)
        op_layout = QVBoxLayout(self.op_group)

        btn_row = QHBoxLayout()
        self.start_btn = QPushButton(tr("btn_start"))
        self.start_btn.setStyleSheet(QSS_BUTTON(COLORS["success"]))
        self.start_btn.setToolTip(tr("tip_start"))

        self.stop_btn = QPushButton(tr("btn_stop"))
        self.stop_btn.setStyleSheet(QSS_BUTTON(COLORS["danger"]))
        self.stop_btn.setEnabled(False)
        self.stop_btn.setToolTip(tr("tip_stop"))

        btn_row.addWidget(self.start_btn)
        btn_row.addWidget(self.stop_btn)
        op_layout.addLayout(btn_row)

        extra_row = QHBoxLayout()
        self.export_btn = QPushButton(tr("btn_export"))
        self.export_btn.setStyleSheet(QSS_BUTTON())
        self.export_btn.setToolTip(tr("tip_export"))

        self.clear_btn = QPushButton(tr("btn_clear"))
        self.clear_btn.setStyleSheet(QSS_BUTTON(COLORS["warning"]))
        self.clear_btn.setToolTip(tr("tip_clear"))

        extra_row.addWidget(self.export_btn)
        extra_row.addWidget(self.clear_btn)
        op_layout.addLayout(extra_row)
        self._layout.addWidget(self.op_group)

        self.log_group = QGroupBox(tr("log_group"))
        self.log_group.setStyleSheet(QSS_GROUPBOX)
        log_layout = QVBoxLayout(self.log_group)
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setMinimumHeight(200)
        log_layout.addWidget(self.log_edit)
        self._layout.addWidget(self.log_group)

    def apply_language(self):
        self.op_group.setTitle(tr("op_group"))
        self.start_btn.setText(tr("btn_start"))
        self.start_btn.setToolTip(tr("tip_start"))
        self.stop_btn.setText(tr("btn_stop"))
        self.stop_btn.setToolTip(tr("tip_stop"))
        self.export_btn.setText(tr("btn_export"))
        self.export_btn.setToolTip(tr("tip_export"))
        self.clear_btn.setText(tr("btn_clear"))
        self.clear_btn.setToolTip(tr("tip_clear"))
        self.log_group.setTitle(tr("log_group"))


class ConfigurationTab(BaseTab):
    def __init__(self, engine, parent=None):
        super().__init__(engine, parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(10, 10, 10, 10)

        self.net_group = QGroupBox(tr("cfg_net_group"))
        self.net_group.setStyleSheet(QSS_GROUPBOX)
        net_layout = QVBoxLayout(self.net_group)

        iface_row = QHBoxLayout()
        self._iface_lbl = QLabel(tr("cfg_iface_lbl"))
        iface_row.addWidget(self._iface_lbl)
        self.iface_combo = QComboBox()
        self.iface_combo.setStyleSheet(QSS_COMBO)

        self.update_ifaces_btn = QPushButton("🌐")
        self.update_ifaces_btn.setToolTip(tr("cfg_iface_tip"))
        self.update_ifaces_btn.setStyleSheet(QSS_BUTTON())
        self.update_ifaces_btn.setFixedWidth(40)

        iface_row.addWidget(self.iface_combo)
        iface_row.addWidget(self.update_ifaces_btn)
        net_layout.addLayout(iface_row)

        prof_row = QHBoxLayout()
        self._profile_lbl = QLabel(tr("cfg_profile_lbl"))
        prof_row.addWidget(self._profile_lbl)
        self.profile_combo = QComboBox()
        self.profile_combo.setStyleSheet(QSS_COMBO)
        self.profile_combo.addItem(tr("cfg_profile_home"), "home")
        self.profile_combo.addItem(tr("cfg_profile_pme"), "pme")
        self.profile_combo.addItem(tr("cfg_profile_dc"), "datacenter")
        self.profile_combo.setToolTip(tr("cfg_profile_tip"))
        prof_row.addWidget(self.profile_combo)
        net_layout.addLayout(prof_row)

        self.autoblock_chk = QCheckBox(tr("cfg_autoblock"))
        self.autoblock_chk.setStyleSheet(f"color: {COLORS['text']}; font-weight: 600;")
        self.autoblock_chk.setToolTip(tr("cfg_autoblock_tip"))
        net_layout.addWidget(self.autoblock_chk)
        self._layout.addWidget(self.net_group)

        self.ai_group = QGroupBox(tr("cfg_ai_group"))
        self.ai_group.setStyleSheet(QSS_GROUPBOX)
        ai_layout = QVBoxLayout(self.ai_group)
        self.ai_controls = {}
        base_cfg = getattr(engine, "get_config_snapshot", lambda: {})() or {}
        ai_thresh = base_cfg.get("ai_thresholds") or DEFAULT_CONFIG.get(
            "ai_thresholds", {}
        )

        for p_id, p_name in [
            ("home", "Home"),
            ("pme", "PME"),
            ("datacenter", "Datacenter"),
        ]:
            row = QHBoxLayout()
            row.addWidget(QLabel(f"{p_name}:"))
            s = QSlider(Qt.Orientation.Horizontal)
            s.setRange(-90, 20)

            def_val = ai_thresh.get(p_id, -0.15)
            s.setValue(int(def_val * 100))
            v_lbl = QLabel(f"{def_val:.2f}")
            v_lbl.setFixedWidth(40)
            s.setToolTip(tr("cfg_slider_tip"))

            row.addWidget(s)
            row.addWidget(v_lbl)
            ai_layout.addLayout(row)
            self.ai_controls[p_id] = (s, v_lbl)

        self.reset_btn = QPushButton(tr("cfg_reset"))
        self.reset_btn.setToolTip(tr("cfg_reset_tip"))
        self.reset_btn.setStyleSheet(QSS_BUTTON(COLORS["warning"]))
        self.reset_btn.setFixedWidth(200)

        self.apply_btn = QPushButton(tr("cfg_save"))
        self.apply_btn.setToolTip(tr("cfg_save_tip"))
        self.apply_btn.setStyleSheet(QSS_BUTTON(COLORS["success"]))
        self.apply_btn.setFixedWidth(200)

        footer_row = QHBoxLayout()
        footer_row.addWidget(self.reset_btn)
        footer_row.addWidget(self.apply_btn)
        ai_layout.addLayout(footer_row)

        self._layout.addWidget(self.ai_group)
        self._layout.addStretch()

    def apply_language(self):
        self.net_group.setTitle(tr("cfg_net_group"))
        self._iface_lbl.setText(tr("cfg_iface_lbl"))
        self.update_ifaces_btn.setToolTip(tr("cfg_iface_tip"))
        self._profile_lbl.setText(tr("cfg_profile_lbl"))
        self.profile_combo.setItemText(0, tr("cfg_profile_home"))
        self.profile_combo.setItemText(1, tr("cfg_profile_pme"))
        self.profile_combo.setItemText(2, tr("cfg_profile_dc"))
        self.profile_combo.setToolTip(tr("cfg_profile_tip"))
        self.autoblock_chk.setText(tr("cfg_autoblock"))
        self.autoblock_chk.setToolTip(tr("cfg_autoblock_tip"))
        self.ai_group.setTitle(tr("cfg_ai_group"))
        for s, _ in self.ai_controls.values():
            s.setToolTip(tr("cfg_slider_tip"))
        self.reset_btn.setText(tr("cfg_reset"))
        self.reset_btn.setToolTip(tr("cfg_reset_tip"))
        self.apply_btn.setText(tr("cfg_save"))
        self.apply_btn.setToolTip(tr("cfg_save_tip"))


class BlockedTab(BaseTab):
    def __init__(self, engine, parent=None):
        super().__init__(engine, parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(10, 10, 10, 10)

        self.group = QGroupBox(tr("blk_group"))
        self.group.setStyleSheet(QSS_GROUPBOX)
        layout = QVBoxLayout(self.group)

        self._warn_lbl = QLabel(tr("blk_warn"))
        self._warn_lbl.setStyleSheet(f"color: {COLORS['warning']}; font-size: 11px;")
        layout.addWidget(self._warn_lbl)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels([
            tr("blk_col_ip"), tr("blk_col_time"),
            tr("blk_col_pps"), tr("blk_col_action"),
        ])
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table)

        btn_row = QHBoxLayout()
        self.unblock_all_btn = QPushButton(tr("blk_unblock_all"))
        self.unblock_all_btn.setToolTip(tr("blk_unblock_tip"))
        self.unblock_all_btn.setStyleSheet(QSS_BUTTON(COLORS["success"]))
        self.unblock_all_btn.setFixedWidth(200)
        btn_row.addWidget(self.unblock_all_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self._layout.addWidget(self.group)

    def apply_language(self):
        self.group.setTitle(tr("blk_group"))
        self._warn_lbl.setText(tr("blk_warn"))
        self.table.setHorizontalHeaderLabels([
            tr("blk_col_ip"), tr("blk_col_time"),
            tr("blk_col_pps"), tr("blk_col_action"),
        ])
        self.unblock_all_btn.setText(tr("blk_unblock_all"))
        self.unblock_all_btn.setToolTip(tr("blk_unblock_tip"))


class WhitelistTab(BaseTab):
    def __init__(self, engine, parent=None):
        super().__init__(engine, parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(10, 10, 10, 10)

        self.wl_group = QGroupBox(tr("wl_group"))
        self.wl_group.setStyleSheet(QSS_GROUPBOX)
        wl_layout = QVBoxLayout(self.wl_group)

        wl_in_row = QHBoxLayout()
        self.wl_input = QLineEdit()
        self.wl_input.setPlaceholderText(tr("wl_placeholder"))
        self.wl_input.setStyleSheet(QSS_INPUT)
        self.wl_add_btn = QPushButton(tr("wl_add"))
        self.wl_add_btn.setToolTip(tr("wl_add_tip"))
        self.wl_add_btn.setStyleSheet(QSS_BUTTON())

        wl_in_row.addWidget(self.wl_input)
        wl_in_row.addWidget(self.wl_add_btn)
        wl_layout.addLayout(wl_in_row)

        self.wl_list = QListWidget()
        self.wl_list.setAlternatingRowColors(True)
        self.wl_list.setStyleSheet(QSS_LIST)
        wl_layout.addWidget(self.wl_list)

        wl_btn_row = QHBoxLayout()
        self.wl_remove_btn = QPushButton(tr("wl_remove"))
        self.wl_remove_btn.setToolTip(tr("wl_remove_tip"))
        self.wl_remove_btn.setStyleSheet(QSS_BUTTON(COLORS["warning"]))

        self.wl_clear_btn = QPushButton(tr("wl_clear"))
        self.wl_clear_btn.setToolTip(tr("wl_clear_tip"))
        self.wl_clear_btn.setStyleSheet(QSS_BUTTON(COLORS["danger"]))

        wl_btn_row.addWidget(self.wl_remove_btn)
        wl_btn_row.addWidget(self.wl_clear_btn)
        wl_layout.addLayout(wl_btn_row)

        self._layout.addWidget(self.wl_group)

    def apply_language(self):
        self.wl_group.setTitle(tr("wl_group"))
        self.wl_input.setPlaceholderText(tr("wl_placeholder"))
        self.wl_add_btn.setText(tr("wl_add"))
        self.wl_add_btn.setToolTip(tr("wl_add_tip"))
        self.wl_remove_btn.setText(tr("wl_remove"))
        self.wl_remove_btn.setToolTip(tr("wl_remove_tip"))
        self.wl_clear_btn.setText(tr("wl_clear"))
        self.wl_clear_btn.setToolTip(tr("wl_clear_tip"))
