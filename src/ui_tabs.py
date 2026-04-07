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
from ui_components import COLORS
from config_manager import DEFAULT_CONFIG


class BaseTab(QWidget):
    """Classe base para fornecer estilos comuns a todas as abas."""

    def __init__(self, engine, parent=None):
        super().__init__(parent)
        self.engine = engine

    def _group_style(self, border_col=None, title_col=None):
        border_col = border_col or COLORS["border"]
        title_col = title_col or COLORS["text_dim"]
        return f"""
            QGroupBox {{
                color: {COLORS['text_dim']};
                font-size: 12px;
                font-weight: 600;
                border: 1px solid {border_col};
                border-radius: 8px;
                margin-top: 8px;
                padding-top: 8px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 6px;
                color: {title_col};
            }}
        """

    def _btn_style(self, hover_color=COLORS["accent"]):
        return f"""
            QPushButton {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['text_dim']};
                border: 1px solid {COLORS['border']};
                padding: 8px 16px;
                border-radius: 10px;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: {COLORS['bg_panel']};
                color: {COLORS['text']};
                border: 1px solid {hover_color};
            }}
            QPushButton:disabled {{
                color: {COLORS['text_dim']}55;
                background-color: transparent;
            }}
        """

    def _input_style(self):
        return f"""
            QLineEdit {{
                background: {COLORS['bg_deep']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                padding: 8px;
                color: {COLORS['text']};
            }}
            QLineEdit:focus {{
                border: 1px solid {COLORS['accent']};
            }}
        """

    def _list_style(self):
        return f"""
            QListWidget {{
                background: {COLORS['bg_deep']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                color: {COLORS['text']};
                padding: 5px;
            }}
        """

    def _combo_style(self):
        return f"""
            QComboBox {{
                background: {COLORS['bg_deep']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                padding: 5px 10px;
                color: {COLORS['text']};
            }}
            QComboBox::drop-down {{
                border: 0px;
                padding-right: 10px;
            }}
            QComboBox QAbstractItemView {{
                background: {COLORS['bg_card']};
                color: {COLORS['text']};
                selection-background-color: {COLORS['accent']};
                border: 1px solid {COLORS['border']};
            }}
        """


class OperationTab(BaseTab):
    def __init__(self, engine, parent=None):
        super().__init__(engine, parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(10, 10, 10, 10)
        self._layout.setSpacing(10)

        self.op_group = QGroupBox("🕹️ Painel de Operação")
        self.op_group.setStyleSheet(self._group_style())
        op_layout = QVBoxLayout(self.op_group)

        btn_row = QHBoxLayout()
        self.start_btn = QPushButton("▶  Iniciar Monitoramento")
        self.start_btn.setStyleSheet(self._btn_style(COLORS["success"]))
        self.start_btn.setToolTip(
            "Inicia a captura de pacotes e análise em tempo real (Requer Admin)."
        )

        self.stop_btn = QPushButton("⏹  Parar")
        self.stop_btn.setStyleSheet(self._btn_style(COLORS["danger"]))
        self.stop_btn.setEnabled(False)
        self.stop_btn.setToolTip("Interrompe a captura e desliga o motor de análise.")

        btn_row.addWidget(self.start_btn)
        btn_row.addWidget(self.stop_btn)
        op_layout.addLayout(btn_row)

        extra_row = QHBoxLayout()
        self.export_btn = QPushButton("📊  Exportar Ataques (CSV)")
        self.export_btn.setStyleSheet(self._btn_style())
        self.export_btn.setToolTip(
            "Exporta o histórico de ataques confirmados para um arquivo CSV."
        )

        self.clear_btn = QPushButton("🗑  Limpar")
        self.clear_btn.setStyleSheet(self._btn_style(COLORS["warning"]))
        self.clear_btn.setToolTip(
            "Limpa o console de eventos e o histórico atual da UI."
        )

        extra_row.addWidget(self.export_btn)
        extra_row.addWidget(self.clear_btn)
        op_layout.addLayout(extra_row)
        self._layout.addWidget(self.op_group)

        self.log_group = QGroupBox("📋 Log de Eventos")
        self.log_group.setStyleSheet(self._group_style())
        log_layout = QVBoxLayout(self.log_group)
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setMinimumHeight(200)
        log_layout.addWidget(self.log_edit)
        self._layout.addWidget(self.log_group)


class ConfigurationTab(BaseTab):
    def __init__(self, engine, parent=None):
        super().__init__(engine, parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(10, 10, 10, 10)

        self.net_group = QGroupBox("⚙️ Configurações de Rede")
        self.net_group.setStyleSheet(self._group_style(COLORS["border"]))
        net_layout = QVBoxLayout(self.net_group)

        iface_row = QHBoxLayout()
        iface_row.addWidget(QLabel("Interface:"))
        self.iface_combo = QComboBox()
        self.iface_combo.setStyleSheet(self._combo_style())

        self.update_ifaces_btn = QPushButton("🌐")
        self.update_ifaces_btn.setToolTip("Atualizar Interfaces")
        self.update_ifaces_btn.setStyleSheet(self._btn_style())
        self.update_ifaces_btn.setFixedWidth(40)

        iface_row.addWidget(self.iface_combo)
        iface_row.addWidget(self.update_ifaces_btn)
        net_layout.addLayout(iface_row)

        prof_row = QHBoxLayout()
        prof_row.addWidget(QLabel("Perfil de IA:"))
        self.profile_combo = QComboBox()
        self.profile_combo.setStyleSheet(self._combo_style())
        self.profile_combo.addItem("🏡 Doméstico (Sensível)", "home")
        self.profile_combo.addItem("🏢 Comercial/PME (Equilibrado)", "pme")
        self.profile_combo.addItem("🚀 Datacenter (Alta Vazão)", "datacenter")
        self.profile_combo.setToolTip(
            "Define a sensibilidade da detecção:\n"
            "• Doméstico: Dispara com poucos PPS extras.\n"
            "• PME: Tolerância moderada a picos de tráfego.\n"
            "• Datacenter: Apenas ataques massivos são bloqueados."
        )
        prof_row.addWidget(self.profile_combo)
        net_layout.addLayout(prof_row)

        self.autoblock_chk = QCheckBox("🔒  Bloqueio Automático via Firewall")
        self.autoblock_chk.setStyleSheet(f"color: {COLORS['text']}; font-weight: 600;")
        self.autoblock_chk.setToolTip(
            "Se ativado, IPs confirmados como ataque serão bloqueados automaticamente via Firewall."
        )
        net_layout.addWidget(self.autoblock_chk)
        self._layout.addWidget(self.net_group)

        self.ai_group = QGroupBox("🧠 Sensibilidade da IA (Isolation Forest)")
        self.ai_group.setStyleSheet(
            self._group_style(COLORS["accent2"] + "55", COLORS["accent2"])
        )
        ai_layout = QVBoxLayout(self.ai_group)
        self.ai_controls = {}

        for p_id, p_name in [
            ("home", "Home"),
            ("pme", "PME"),
            ("datacenter", "Datacenter"),
        ]:
            row = QHBoxLayout()
            row.addWidget(QLabel(f"{p_name}:"))
            s = QSlider(Qt.Orientation.Horizontal)
            s.setRange(-90, 20)

            # Carregamos valores do dicionário ativo com fallback direto ao DEFAULT_CONFIG
            base_cfg = getattr(engine, "get_config_snapshot", lambda: {})() or {}
            ai_thresh = base_cfg.get("ai_thresholds") or DEFAULT_CONFIG.get(
                "ai_thresholds", {}
            )
            def_val = ai_thresh.get(p_id, -0.15)

            s.setValue(int(def_val * 100))
            v_lbl = QLabel(f"{def_val:.2f}")
            v_lbl.setFixedWidth(40)

            s.setToolTip(
                "Ajuste da Sensibilidade da IA:\n"
                "- Quanto MAIS NEGATIVO (ex: -0.50), MAIS RÍGIDA a detecção (mais alertas).\n"
                "- Quanto MAIS POSITIVO (ex: 0.10), MAIS TOLERANTE a detecção (menos falsos-positivos)."
            )

            row.addWidget(s)
            row.addWidget(v_lbl)
            ai_layout.addLayout(row)
            self.ai_controls[p_id] = (s, v_lbl)

        self.reset_btn = QPushButton("🔄 Restaurar Padrões")
        self.reset_btn.setToolTip(
            "Redefine todos os thresholds de IA para os valores originais recomendados."
        )
        self.reset_btn.setStyleSheet(self._btn_style(COLORS["warning"]))
        self.reset_btn.setFixedWidth(200)

        self.apply_btn = QPushButton("💾 Salvar Configurações")
        self.apply_btn.setToolTip(
            "Aplica permanentemente as configurações desta aba ao motor ativo."
        )
        self.apply_btn.setStyleSheet(self._btn_style(COLORS["success"]))
        self.apply_btn.setFixedWidth(200)

        footer_row = QHBoxLayout()
        footer_row.addWidget(self.reset_btn)
        footer_row.addWidget(self.apply_btn)
        ai_layout.addLayout(footer_row)

        self._layout.addWidget(self.ai_group)
        self._layout.addStretch()


class BlockedTab(BaseTab):
    def __init__(self, engine, parent=None):
        super().__init__(engine, parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(10, 10, 10, 10)

        self.group = QGroupBox("🔒 IPs Bloqueados via Firewall")
        self.group.setStyleSheet(
            self._group_style(COLORS["danger"] + "55", COLORS["danger"])
        )
        layout = QVBoxLayout(self.group)

        warn = QLabel(
            "⚠️  IPs listados abaixo estão bloqueados no Firewall desta sessão."
        )
        warn.setStyleSheet(f"color: {COLORS['warning']}; font-size: 11px;")
        layout.addWidget(warn)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(
            ["IP Bloqueado", "Horário", "Intensidade (PPS)", "Ação"]
        )
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)

        btn_row = QHBoxLayout()
        self.unblock_all_btn = QPushButton("🔓  Desbloquear Todos")
        self.unblock_all_btn.setToolTip(
            "Remove TODAS as restrições atuais do Firewall e libera os IPs listados."
        )
        self.unblock_all_btn.setStyleSheet(self._btn_style(COLORS["success"]))
        self.unblock_all_btn.setFixedWidth(200)
        btn_row.addWidget(self.unblock_all_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self._layout.addWidget(self.group)


class WhitelistTab(BaseTab):
    def __init__(self, engine, parent=None):
        super().__init__(engine, parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(10, 10, 10, 10)

        self.wl_group = QGroupBox("🛡️ Whitelist (Exceções de IP/Rede)")
        self.wl_group.setStyleSheet(self._group_style(COLORS["accent"]))
        wl_layout = QVBoxLayout(self.wl_group)

        wl_in_row = QHBoxLayout()
        self.wl_input = QLineEdit()
        self.wl_input.setPlaceholderText("Digite o IP (ex: 192.168.0.50)")
        self.wl_input.setStyleSheet(self._input_style())
        self.wl_add_btn = QPushButton("➕ Adicionar")
        self.wl_add_btn.setToolTip(
            "Adiciona o IP/Rede acima à lista de confiança (NUNCA será bloqueado)."
        )
        self.wl_add_btn.setStyleSheet(self._btn_style())

        wl_in_row.addWidget(self.wl_input)
        wl_in_row.addWidget(self.wl_add_btn)
        wl_layout.addLayout(wl_in_row)

        self.wl_list = QListWidget()
        self.wl_list.setStyleSheet(self._list_style())
        wl_layout.addWidget(self.wl_list)

        wl_btn_row = QHBoxLayout()
        self.wl_remove_btn = QPushButton("➖ Remover")
        self.wl_remove_btn.setToolTip("Remove o item selecionado da Whitelist.")
        self.wl_remove_btn.setStyleSheet(self._btn_style(COLORS["warning"]))

        self.wl_clear_btn = QPushButton("🗑️ Limpar Tudo")
        self.wl_clear_btn.setToolTip("Remove todos os IPs e redes da Whitelist.")
        self.wl_clear_btn.setStyleSheet(self._btn_style(COLORS["danger"]))

        wl_btn_row.addWidget(self.wl_remove_btn)
        wl_btn_row.addWidget(self.wl_clear_btn)
        wl_layout.addLayout(wl_btn_row)

        self._layout.addWidget(self.wl_group)
