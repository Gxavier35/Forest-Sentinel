import collections
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QFrame,
    QGraphicsDropShadowEffect,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QLinearGradient, QGradient, QPainter, QBrush, QPen
from PyQt6.QtCharts import QChart, QChartView, QLineSeries, QValueAxis, QAreaSeries

COLORS = {
    "bg_deep": "#05070C",  # Deep Space
    "bg_panel": "#090C16",  # Midnight
    "bg_card": "#101422",  # Dark Slate
    "accent": "#00D4FF",  # Vivid Cyan
    "accent2": "#7B2FFF",  # Neon Purple
    "success": "#00E896",  # Emerald
    "danger": "#FF3366",  # Rose
    "warning": "#FFB020",  # Gold
    "text": "#F0F2F8",  # Off-white
    "text_dim": "#5C6B89",  # Gray-blue
    "border": "#1B2238",  # Stealth Border
    "chart_fwd": "#00D4FF",
    "chart_att": "#FF3366",
}


class MetricCard(QFrame):
    def __init__(self, title, value="0", unit="", color=COLORS["accent"], parent=None):
        super().__init__(parent)
        self.color = color
        self.setFixedHeight(110)
        self.setObjectName("MetricCard")
        self.setStyleSheet(f"""
            #MetricCard {{
                background: transparent;
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)

        self.title_lbl = QLabel(title)
        self.title_lbl.setStyleSheet(
            f"color: {COLORS['text_dim']}; font-size: 12px; font-weight: 600;"
        )

        self.value_lbl = QLabel(value)
        self.value_lbl.setStyleSheet(
            f"color: {color}; font-size: 28px; font-weight: 700;"
        )

        self.unit_lbl = QLabel(unit)
        self.unit_lbl.setStyleSheet(f"color: {COLORS['text_dim']}; font-size: 11px;")

        layout.addWidget(self.title_lbl)
        layout.addWidget(self.value_lbl)
        layout.addWidget(self.unit_lbl)

    def update_value(self, val):
        self.value_lbl.setText(str(val))


class ActivityChart(QWidget):
    MAX_POINTS = 60

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_chart()
        self._chart_view = QChartView(self._chart)
        self._chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self._chart_view.setStyleSheet("background: transparent;")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._chart_view)

        self._normal_data = collections.deque(maxlen=self.MAX_POINTS)
        self._attack_data = collections.deque(maxlen=self.MAX_POINTS)
        self._t = 0

    def _setup_chart(self):
        self._chart = QChart()
        self._chart.setBackgroundBrush(QBrush(Qt.GlobalColor.transparent))
        self._chart.setMargins(self._chart.margins().__class__(0, 0, 0, 0))
        self._chart.legend().setVisible(True)
        self._chart.legend().setLabelColor(QColor(COLORS["text_dim"]))
        self._chart.setTitle("")
        self._chart.layout().setContentsMargins(0, 0, 0, 0)

        self._series_normal = QLineSeries()
        self._series_normal.setName("Normal")
        pen = self._series_normal.pen()
        pen.setColor(QColor(COLORS["chart_fwd"]))
        pen.setWidth(2)
        self._series_normal.setPen(pen)

        self._series_attack = QLineSeries()
        self._series_attack.setName("Ataque")
        pen2 = self._series_attack.pen()
        pen2.setColor(QColor(COLORS["chart_att"]))
        pen2.setWidth(2)
        self._series_attack.setPen(pen2)

        self._chart.addSeries(self._series_normal)

        area = QAreaSeries(self._series_normal)
        area.setName("")
        grad = QLinearGradient(0, 0, 0, 1)
        grad.setCoordinateMode(QGradient.CoordinateMode.ObjectBoundingMode)
        grad.setColorAt(0.0, QColor(COLORS["chart_fwd"] + "55"))
        grad.setColorAt(1.0, QColor(COLORS["chart_fwd"] + "00"))
        area.setBrush(QBrush(grad))
        no_pen = QPen()
        no_pen.setStyle(Qt.PenStyle.NoPen)
        area.setPen(no_pen)

        self._chart.addSeries(area)
        # Oculta o marcador da área na legenda (evita o "quadradinho" vazio)
        if self._chart.legend().markers(area):
            self._chart.legend().markers(area)[0].setVisible(False)

        self._chart.addSeries(self._series_attack)

        self._axis_x = QValueAxis()
        self._axis_x.setRange(0, self.MAX_POINTS)
        self._axis_x.setLabelFormat("")
        self._axis_x.setLabelsColor(QColor(COLORS["text_dim"]))
        self._axis_x.setGridLineColor(QColor(COLORS["border"]))
        self._axis_x.setTitleText("")

        self._axis_y = QValueAxis()
        self._axis_y.setRange(0, 10)
        self._axis_y.setLabelsColor(QColor(COLORS["text_dim"]))
        self._axis_y.setGridLineColor(QColor(COLORS["border"]))
        self._axis_y.setTitleText("Fluxos/s")
        self._axis_y.setTitleBrush(QBrush(QColor(COLORS["text_dim"])))

        self._chart.addAxis(self._axis_x, Qt.AlignmentFlag.AlignBottom)
        self._chart.addAxis(self._axis_y, Qt.AlignmentFlag.AlignLeft)

        for s in [self._series_normal, area, self._series_attack]:
            s.attachAxis(self._axis_x)
            s.attachAxis(self._axis_y)

    def push(self, normal_count: int, attack_count: int):
        self._t += 1
        self._normal_data.append(normal_count)
        self._attack_data.append(attack_count)

        self._series_normal.clear()
        self._series_attack.clear()
        start = max(0, self._t - self.MAX_POINTS)
        for i, (n, a) in enumerate(zip(self._normal_data, self._attack_data)):
            x = start + i
            self._series_normal.append(x, n)
            self._series_attack.append(x, a)

        mx = max(
            max(self._normal_data, default=0), max(self._attack_data, default=0), 10
        )
        self._axis_y.setRange(0, mx * 1.2)
        self._axis_x.setRange(start, start + self.MAX_POINTS)


class AlertBanner(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("AlertBanner")
        self._visible = False
        self._alpha = 0
        self.hide()
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(f"""
            #AlertBanner {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 {COLORS['danger']}, stop:0.02 {COLORS['danger']}, 
                    stop:0.021 {COLORS['bg_panel']}, stop:1 {COLORS['bg_panel']});
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
            }}
            #AlertBanner[blink="true"] {{
                background: {COLORS['danger']}AA;
                border: 1px solid {COLORS['danger']};
                border-radius: 10px;
            }}
            QLabel {{ border: none; background: transparent; }}
        """)

        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(12, 4, 12, 4)
        self._layout.setSpacing(10)

        icon_lbl = QLabel("🚨")
        icon_lbl.setStyleSheet("font-size: 20px;")

        self._text_lbl = QLabel("ATAQUE DDOS DETECTADO")
        self._text_lbl.setStyleSheet(f"""
            color: #FFFFFF;
            margin: 0px;
            padding: 4px 8px;
            font-size: 12px;
            font-weight: 800;
        """)

        self._sub_lbl = QLabel("")
        self._sub_lbl.setStyleSheet(
            f"color: {COLORS['text']}; font-size: 11px; font-weight: 600; font-family: 'Consolas', monospace;"
        )

        txt_col = QVBoxLayout()
        txt_col.setSpacing(0)
        txt_col.addWidget(self._text_lbl)
        txt_col.addWidget(self._sub_lbl)

        self._layout.addWidget(icon_lbl)
        self._layout.addLayout(txt_col)

        self._blink_timer = QTimer(self)
        self._blink_timer.timeout.connect(self._blink)
        self._blink_state = True

        self._auto_hide_timer = QTimer(self)
        self._auto_hide_timer.setSingleShot(True)
        self._auto_hide_timer.timeout.connect(self.hide_alert)

    def show_alert(self, msg: str = "", duration_ms: int = 10000):
        if ":" in msg:
            title, subtitle = msg.split(":", 1)
            self._text_lbl.setText(title.strip().upper())
            self._sub_lbl.setText(subtitle.strip())
        else:
            self._sub_lbl.setText(msg)
        self.show()
        self._blink_timer.start(400)
        self._auto_hide_timer.start(duration_ms)
        self._visible = True

    def hide_alert(self):
        self._blink_timer.stop()
        self._auto_hide_timer.stop()
        self.hide()
        self._visible = False

    def _blink(self):
        self._blink_state = not self._blink_state
        self.setProperty("blink", self._blink_state)
        self.style().unpolish(self)
        self.style().polish(self)
