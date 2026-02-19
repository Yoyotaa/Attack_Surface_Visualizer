#!/usr/bin/env python3

import sys
import os
from pathlib import Path
from typing import List, Dict, Optional
import math

import psutil  # type: ignore
import networkx as nx  # type: ignore
import numpy as np  # type: ignore
from PyQt5 import QtWidgets, QtGui, QtCore  # type: ignore


# Mapping of commonly known ports to service names
SERVICE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    11211: "Memcached",
    1521: "OracleDB",
    19000: "ElasticSearch",
}

SECRET_KEYWORDS = [
    "secret", "token", "password", "key", "access_key", "private_key",
    "api_key", "auth", "credential", "passphrase"
]

class HoverEllipseItem(QtWidgets.QGraphicsEllipseItem):
    def __init__(self, rect: QtCore.QRectF, color: QtGui.QColor):
        super().__init__(rect)
        self.base_color = color
        self.base_pen = QtGui.QPen(color.darker(130), 1)
        self.hover_pen = QtGui.QPen(color.lighter(110), 2)
        self.setPen(self.base_pen)
        self.setBrush(QtGui.QBrush(color))

        self.shadow = QtWidgets.QGraphicsDropShadowEffect()
        self.shadow.setBlurRadius(18)
        self.shadow.setOffset(0, 0)
        self.shadow.setColor(color)
        self.setGraphicsEffect(self.shadow)

        self.setAcceptHoverEvents(True)
        self.setCursor(QtCore.Qt.PointingHandCursor)
        self.setTransformOriginPoint(self.rect().center())
        self.setAcceptDrops(False)

    def _animate_to(self, target_scale: float, target_blur: int):
        # Stop previous animations cleanly (avoid C++ dangling)
        if hasattr(self, "_scale_anim") and self._scale_anim:
            self._scale_anim.stop()
        if hasattr(self, "_blur_anim") and self._blur_anim:
            self._blur_anim.stop()

        start_scale = float(self.scale())
        start_blur = float(self.shadow.blurRadius())

        self._scale_anim = QtCore.QVariantAnimation()
        self._scale_anim.setDuration(140)
        self._scale_anim.setEasingCurve(QtCore.QEasingCurve.OutCubic)
        self._scale_anim.setStartValue(start_scale)
        self._scale_anim.setEndValue(float(target_scale))
        self._scale_anim.valueChanged.connect(lambda v: self.setScale(float(v)))

        self._blur_anim = QtCore.QVariantAnimation()
        self._blur_anim.setDuration(140)
        self._blur_anim.setEasingCurve(QtCore.QEasingCurve.OutCubic)
        self._blur_anim.setStartValue(start_blur)
        self._blur_anim.setEndValue(float(target_blur))
        self._blur_anim.valueChanged.connect(lambda v: self.shadow.setBlurRadius(float(v)))

        self._scale_anim.start()
        self._blur_anim.start()

    def hoverEnterEvent(self, event):
        self.setPen(self.hover_pen)
        self._animate_to(1.18, 34)
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        self.setPen(self.base_pen)
        self._animate_to(1.0, 18)
        super().hoverLeaveEvent(event)


class HoverPathItem(QtWidgets.QGraphicsPathItem):
    def __init__(self, path: QtGui.QPainterPath, color: QtGui.QColor):
        super().__init__(path)
        self.base_color = color
        self.base_pen = QtGui.QPen(color.darker(130), 1)
        self.hover_pen = QtGui.QPen(color.lighter(110), 2)
        self.setPen(self.base_pen)
        self.setBrush(QtGui.QBrush(color))

        self.shadow = QtWidgets.QGraphicsDropShadowEffect()
        self.shadow.setBlurRadius(20)
        self.shadow.setOffset(0, 0)
        self.shadow.setColor(color)
        self.setGraphicsEffect(self.shadow)

        self.setAcceptHoverEvents(True)
        self.setCursor(QtCore.Qt.PointingHandCursor)
        self.setTransformOriginPoint(self.boundingRect().center())

    def _animate_to(self, target_scale: float, target_blur: int):
        if hasattr(self, "_scale_anim") and self._scale_anim:
            self._scale_anim.stop()
        if hasattr(self, "_blur_anim") and self._blur_anim:
            self._blur_anim.stop()

        start_scale = float(self.scale())
        start_blur = float(self.shadow.blurRadius())

        self._scale_anim = QtCore.QVariantAnimation()
        self._scale_anim.setDuration(140)
        self._scale_anim.setEasingCurve(QtCore.QEasingCurve.OutCubic)
        self._scale_anim.setStartValue(start_scale)
        self._scale_anim.setEndValue(float(target_scale))
        self._scale_anim.valueChanged.connect(lambda v: self.setScale(float(v)))

        self._blur_anim = QtCore.QVariantAnimation()
        self._blur_anim.setDuration(140)
        self._blur_anim.setEasingCurve(QtCore.QEasingCurve.OutCubic)
        self._blur_anim.setStartValue(start_blur)
        self._blur_anim.setEndValue(float(target_blur))
        self._blur_anim.valueChanged.connect(lambda v: self.shadow.setBlurRadius(float(v)))

        self._scale_anim.start()
        self._blur_anim.start()

    def hoverEnterEvent(self, event):
        self.setPen(self.hover_pen)
        self._animate_to(1.10, 38)
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        self.setPen(self.base_pen)
        self._animate_to(1.0, 20)
        super().hoverLeaveEvent(event)


class AttackScanner:
    """Performs scanning of ports and environment files."""

    def __init__(self) -> None:
        self.listeners: List[Dict[str, object]] = []
        self.env_files: List[Dict[str, object]] = []
        self.score: int = 0
        self.suggestions: List[str] = []

    def discover_listeners(self) -> None:
        listeners = []
        for conn in psutil.net_connections(kind="inet"):
            if conn.status != psutil.CONN_LISTEN:
                continue
            try:
                if hasattr(conn.laddr, 'ip'):
                    ip = conn.laddr.ip
                    port = conn.laddr.port
                else:
                    ip, port = conn.laddr
            except Exception:
                continue
            pid = conn.pid
            proc_name: Optional[str] = None
            if pid is not None:
                try:
                    proc_name = psutil.Process(pid).name()
                except Exception:
                    proc_name = None
            service = SERVICE_PORTS.get(port)
            risks: List[str] = []
            # Determine risk: exposed if binding to all interfaces
            if ip in ("0.0.0.0", "::"):
                if port in (3306, 5432, 27017, 6379, 11211, 1521, 19000):
                    risks.append("Public DB/service exposed")
                elif port in (22,):
                    risks.append("SSH exposed")
                elif port in (80, 443):
                    risks.append("Web service exposed")
                else:
                    risks.append("Public port exposed")
            listeners.append({
                'ip': ip,
                'port': port,
                'pid': pid,
                'process': proc_name,
                'service': service,
                'risks': risks,
            })
        self.listeners = listeners

    def scan_env_files(self, root: Path) -> None:
        results = []
        for r, _, files in os.walk(root):
            for fname in files:
                if fname.startswith('.env'):
                    fpath = Path(r) / fname
                    exposures: List[Dict[str, str]] = []
                    try:
                        with open(fpath, 'r', encoding='utf-8', errors='ignore') as fh:
                            for line in fh:
                                line = line.strip()
                                if not line or line.startswith('#') or '=' not in line:
                                    continue
                                key, _, value = line.partition('=')
                                key_lower = key.lower()
                                value_lower = value.lower()
                                if any(term in key_lower for term in SECRET_KEYWORDS) or \
                                   any(term in value_lower for term in SECRET_KEYWORDS):
                                    exposures.append({'key': key.strip(), 'line': line.strip()})
                    except Exception:
                        continue
                    if exposures:
                        results.append({'path': str(fpath), 'secrets': exposures})
        self.env_files = results

    def compute_score_and_suggestions(self) -> None:
        score = 0
        suggestions = []
        for l in self.listeners:
            if l['risks']:
                if any(r.startswith('Public DB') for r in l['risks']):
                    score += 20
                    suggestions.append(f"Restrict database port {l['port']} to localhost")
                elif any("SSH" in r for r in l['risks']):
                    score += 15
                    suggestions.append("Limit SSH to local network or change port")
                elif any("Web" in r for r in l['risks']):
                    score += 10
                    suggestions.append("Ensure web service uses TLS and is behind a proxy")
                else:
                    score += 5
                    suggestions.append(f"Close or firewall port {l['port']} if not needed")
        for env in self.env_files:
            score += len(env['secrets']) * 5
            for sec in env['secrets']:
                suggestions.append(f"Remove or mask secret '{sec['key']}' from {env['path']}")
        self.score = score
        # Deduplicate suggestions and keep top 8
        self.suggestions = list(dict.fromkeys(suggestions))[:8]

    def run(self, root: Path, scan_ports: bool, scan_env: bool) -> None:
        if scan_ports:
            self.discover_listeners()
        else:
            self.listeners = []
        if scan_env:
            self.scan_env_files(root)
        else:
            self.env_files = []
        self.compute_score_and_suggestions()



class GraphView(QtWidgets.QGraphicsView):

    node_clicked = QtCore.pyqtSignal(dict)

    def __init__(self, parent: QtWidgets.QWidget = None) -> None:
        super().__init__(parent)
        self.setRenderHints(QtGui.QPainter.Antialiasing | QtGui.QPainter.SmoothPixmapTransform)
        self.setDragMode(QtWidgets.QGraphicsView.ScrollHandDrag)
        self.setViewportUpdateMode(QtWidgets.QGraphicsView.FullViewportUpdate)
        self.setTransformationAnchor(QtWidgets.QGraphicsView.AnchorUnderMouse)
        self.scene = QtWidgets.QGraphicsScene(self)
        self.setScene(self.scene)
        self.setBackgroundBrush(QtGui.QBrush(QtGui.QColor("#0F1418")))
        self.zoom_factor = 1.15
        self._items = []
        self.setMouseTracking(True)
        self.viewport().setMouseTracking(True)

    def wheelEvent(self, event: QtGui.QWheelEvent) -> None:
        factor = self.zoom_factor if event.angleDelta().y() > 0 else 1 / self.zoom_factor
        self.scale(factor, factor)

    def mousePressEvent(self, event: QtGui.QMouseEvent) -> None:
        # Qt donne la liste des items sous la souris, triés par Z (top-first)
        for it in self.items(event.pos()):
            if hasattr(it, "node_payload"):
                self.node_clicked.emit(it.node_payload)
                break

        super().mousePressEvent(event)

    def _glow(self, item, color_hex: str):
        shadow = QtWidgets.QGraphicsDropShadowEffect()
        shadow.setBlurRadius(18)
        shadow.setOffset(0, 0)
        shadow.setColor(QtGui.QColor(color_hex))
        item.setGraphicsEffect(shadow)

    def _add_circle(self, x, y, r, color, tooltip, payload, text=None):
        qcolor = QtGui.QColor(color)
        rect = QtCore.QRectF(x - r, y - r, 2 * r, 2 * r)

        item = HoverEllipseItem(rect, qcolor)
        item.setToolTip(tooltip)
        item.node_payload = payload
        item.setZValue(10)

        self.scene.addItem(item)
        self._items.append(item)

        # Optional centered text (click-through)
        if text is not None and str(text).strip() != "":
            t = self.scene.addText(str(text), QtGui.QFont("Segoe UI", 8, QtGui.QFont.Bold))
            t.setAcceptedMouseButtons(QtCore.Qt.NoButton)
            t.setAcceptHoverEvents(False)
            t.setFlag(QtWidgets.QGraphicsItem.ItemIsSelectable, False)
            t.setZValue(11)
            t.setDefaultTextColor(QtGui.QColor("#E6EDF3"))
            t.setPos(x - t.boundingRect().width() / 2, y - t.boundingRect().height() / 2)
            self._items.append(t)

    def _add_pill(self, x, y, w, h, color, label, payload, always_label=True):
        path = QtGui.QPainterPath()
        rect = QtCore.QRectF(x - w / 2, y - h / 2, w, h)
        path.addRoundedRect(rect, 14, 14)

        qcolor = QtGui.QColor(color)
        item = HoverPathItem(path, qcolor)
        item.node_payload = payload
        item.setZValue(20)
        self.scene.addItem(item)
        self._items.append(item)

        if always_label:
            text = self.scene.addText(str(label), QtGui.QFont("Segoe UI", 9, QtGui.QFont.Bold))
            text.setAcceptedMouseButtons(QtCore.Qt.NoButton)
            text.setAcceptHoverEvents(False)
            text.setFlag(QtWidgets.QGraphicsItem.ItemIsSelectable, False)
            text.setZValue(21)
            text.setDefaultTextColor(QtGui.QColor("#E6EDF3"))
            text.setPos(
                x - text.boundingRect().width() / 2,
                y - text.boundingRect().height() / 2
            )
            self._items.append(text)

    def draw_graph(self, scanner: AttackScanner, show_safe: bool, show_processes: bool, max_ports: int) -> None:
        self.scene.clear()
        self._items = []

        listeners = list(scanner.listeners or [])

        def weight(l):
            risks = l.get("risks") or []
            if not risks:
                return 0
            joined = " ".join(risks)
            if "DB" in joined:
                return 3
            if "SSH" in joined:
                return 2
            return 1

        listeners.sort(key=weight, reverse=True)
        risky = [l for l in listeners if l.get("risks")]
        safe = [l for l in listeners if not l.get("risks")]

        ports_to_show = risky[:max_ports]
        if show_safe:
            rem = max(0, max_ports - len(ports_to_show))
            ports_to_show += safe[:rem]

        w = max(980, self.viewport().width())
        h = max(640, self.viewport().height())
        cx, cy = w/2, h/2
        process_positions = {}  # proc_name -> (x,y)
        process_counts = {}  # proc_name -> count of linked ports
        process_items = {}  # proc_name -> payload
        process_edges = []  # list of (port_x, port_y, proc_name)

        # Host
        self._add_pill(cx, cy, 110, 44, "#00BFA5", "HOST",
                       {"type": "host", "label": "HOST"})

        # Rings
        risky_nodes = [l for l in ports_to_show if l.get("risks")]
        safe_nodes = [l for l in ports_to_show if not l.get("risks")]

        def ring(nodes, radius, base_color, kind):
            if not nodes:
                return
            step = 2 * math.pi / max(1, len(nodes))
            for i, n in enumerate(nodes):
                a = i * step
                x = cx + radius * math.cos(a)
                y = cy + radius * math.sin(a)

                port = n.get("port")
                svc = n.get("service") or "unknown"
                ip = n.get("ip")
                proc = n.get("process")
                risks = n.get("risks") or []

                color = base_color
                if risks:
                    if any("DB" in r for r in risks):
                        color = "#FF5252"
                    elif any("SSH" in r for r in risks):
                        color = "#FF7043"
                    else:
                        color = "#FF8A65"

                tooltip = f"{ip}:{port}  ({svc})\nproc: {proc or 'unknown'}\nrisks: {', '.join(risks) if risks else 'none'}"
                payload = {
                    "type": kind,
                    "ip": ip, "port": port, "service": svc,
                    "process": proc, "risks": risks
                }

                self._add_circle(x, y, 18, color, tooltip, payload, text=str(port))
                line = self.scene.addLine(cx, cy, x, y, QtGui.QPen(QtGui.QColor("#2B3A44"), 1))
                line.setZValue(0)
                line.setAcceptedMouseButtons(QtCore.Qt.NoButton)
                line.setAcceptHoverEvents(False)

                if show_processes and proc:
                    process_counts[proc] = process_counts.get(proc, 0) + 1
                    process_edges.append((x, y, proc))
                    process_items[proc] = {"type": "process", "process": proc, "count": process_counts[proc]}

        ring(risky_nodes, 220, "#FF8A65", "port_risky")
        ring(safe_nodes, 320, "#29B6F6", "port_safe")
        if show_processes and process_counts:
            procs = sorted(process_counts.keys(), key=lambda p: process_counts[p], reverse=True)

            # anneau process plus loin (évite de masquer les ports)
            proc_radius = 430
            if len(procs) > 30:
                proc_radius = 480

            step = 2 * math.pi / max(1, len(procs))
            for i, proc in enumerate(procs):
                a = i * step

                # décalage tangent alterné (anti-chevauchement léger)
                tx, ty = -math.sin(a), math.cos(a)
                spread = 18 if (i % 2 == 0) else -18

                px = cx + proc_radius * math.cos(a) + spread * tx
                py = cy + proc_radius * math.sin(a) + spread * ty

                # label court pour éviter les pills énormes
                label = proc.replace(".exe", "")
                if len(label) > 14:
                    label = label[:12] + "…"

                self._add_pill(
                    px, py, 110, 30,
                    "#7C4DFF",
                    label,
                    {"type": "process", "process": proc, "count": process_counts[proc]},
                    always_label=True
                )

            # Dessiner les liens port -> process (derrière tout)
            for (x, y, proc) in process_edges:
                idx = procs.index(proc)
                a = idx * step
                tx, ty = -math.sin(a), math.cos(a)
                spread = 18 if (idx % 2 == 0) else -18
                px = cx + proc_radius * math.cos(a) + spread * tx
                py = cy + proc_radius * math.sin(a) + spread * ty

                line = self.scene.addLine(x, y, px, py, QtGui.QPen(QtGui.QColor("#3A4B56"), 1))
                line.setZValue(0)
                line.setAcceptedMouseButtons(QtCore.Qt.NoButton)
                line.setAcceptHoverEvents(False)

        # Env cluster (if any)
        if scanner.env_files:
            base_x, base_y = cx, cy + 420
            self._add_pill(base_x, base_y, 150, 36, "#607D8B",
                           f".env findings ({len(scanner.env_files)})",
                           {"type": "env_cluster", "count": len(scanner.env_files)})
            self.scene.addLine(cx, cy, base_x, base_y, QtGui.QPen(QtGui.QColor("#2B3A44"), 1))
            for i, env in enumerate(scanner.env_files[:10]):
                ex = base_x + (i - 4.5) * 95
                ey = base_y + 70
                name = Path(env["path"]).name
                secrets = [s["key"] for s in env.get("secrets", [])]
                self._add_pill(ex, ey, 120, 30, "#9E9D24", name,
                               {"type": "env_file", "path": env["path"], "secrets": secrets}, always_label=False)
                self.scene.addLine(base_x, base_y, ex, ey, QtGui.QPen(QtGui.QColor("#3A4B56"), 1))

        self.scene.setSceneRect(0, 0, w, h)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Attack Surface Visualizer")
        self.resize(1200, 800)
        # Central widget
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        main_layout = QtWidgets.QHBoxLayout(central)
        # Left side: Graph
        self.graph_view = GraphView()
        main_layout.addWidget(self.graph_view, stretch=2)
        # Right side: controls and details
        right_panel = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        # Header with score
        self.score_badge = QtWidgets.QLabel("Attack Surface Score: 0 (LOW)")
        self.score_badge.setAlignment(QtCore.Qt.AlignCenter)
        self.score_badge.setStyleSheet("background-color:#2E7D32; color:#ECEFF1; padding:8px; font-size:18px; font-weight:bold;")
        right_layout.addWidget(self.score_badge)
        self.kpi_label = QtWidgets.QLabel("Risky ports: 0   •   Secrets: 0")
        self.kpi_label.setAlignment(QtCore.Qt.AlignCenter)
        self.kpi_label.setStyleSheet("color:#A9B4C2; padding:6px;")
        right_layout.addWidget(self.kpi_label)

        # Folder selection and options
        form_layout = QtWidgets.QFormLayout()
        self.path_edit = QtWidgets.QLineEdit(str(Path('.').resolve()))
        browse_btn = QtWidgets.QPushButton("Choose folder...")
        browse_btn.clicked.connect(self.choose_folder)
        path_widget = QtWidgets.QWidget()
        path_layout = QtWidgets.QHBoxLayout(path_widget)
        path_layout.setContentsMargins(0, 0, 0, 0)
        path_layout.addWidget(self.path_edit)
        path_layout.addWidget(browse_btn)
        form_layout.addRow("Folder to scan:", path_widget)
        scan_box = QtWidgets.QGroupBox("Scan")
        scan_layout = QtWidgets.QVBoxLayout(scan_box)
        scan_layout.setSpacing(10)

        # Ton widget de path (LineEdit + bouton)
        scan_layout.addLayout(form_layout)  # si form_layout contient path + options + bouton
        right_layout.addWidget(scan_box)

        # Scan options
        self.ports_cb = QtWidgets.QCheckBox("Scan open ports")
        self.ports_cb.setChecked(True)
        self.env_cb = QtWidgets.QCheckBox("Scan .env files")
        self.env_cb.setChecked(True)
        form_layout.addRow(self.ports_cb)
        form_layout.addRow(self.env_cb)
        # Scan button
        scan_btn = QtWidgets.QPushButton("Run scan")
        scan_btn.clicked.connect(self.run_scan)
        form_layout.addRow(scan_btn)

        # Visual options
        vis_box = QtWidgets.QGroupBox("Display")
        vis_layout = QtWidgets.QVBoxLayout(vis_box)
        vis_layout.setSpacing(10)
        right_layout.addWidget(vis_box)
        self.show_safe_cb = QtWidgets.QCheckBox("Show non-risky ports")
        self.show_safe_cb.setChecked(False)
        self.show_proc_cb = QtWidgets.QCheckBox("Show processes")
        self.show_proc_cb.setChecked(False)
        vis_layout.addWidget(self.show_safe_cb)
        vis_layout.addWidget(self.show_proc_cb)
        self.max_ports_spin = QtWidgets.QSpinBox()
        self.max_ports_spin.setRange(10, 300)
        self.max_ports_spin.setValue(60)
        self.max_ports_spin.setSingleStep(10)
        vis_layout.addWidget(QtWidgets.QLabel("Maximum number of ports in the graph"))
        vis_layout.addWidget(self.max_ports_spin)

        # Scroll area for details
        self.details_text = QtWidgets.QTextEdit()
        self.details_text.setReadOnly(True)
        details_box = QtWidgets.QGroupBox("Details")
        details_layout = QtWidgets.QVBoxLayout(details_box)
        details_layout.addWidget(self.details_text)
        right_layout.addWidget(details_box, stretch=1)
        main_layout.addWidget(right_panel, stretch=1)
        # Scanner instance
        self.scanner = AttackScanner()
        self.graph_view.node_clicked.connect(self.on_node_clicked)
        self.set_dark_theme()

    def set_dark_theme(self) -> None:
        self.setStyleSheet("""
        QMainWindow { background-color: #0B0F14; }
        QWidget { color: #E6EDF3; font-family: "Segoe UI"; font-size: 12px; }

        /* Top score badge handled separately */

        /* Inputs */
        QLineEdit {
            background-color: #0F1720;
            color: #E6EDF3;
            border: 1px solid #223041;
            border-radius: 10px;
            padding: 8px 10px;
            selection-background-color: #2563EB;
        }
        QLineEdit:focus { border: 1px solid #3B82F6; }

        QCheckBox { spacing: 10px; }
        QCheckBox::indicator {
            width: 18px; height: 18px;
            border-radius: 6px;
            border: 1px solid #223041;
            background: #0F1720;
        }
        QCheckBox::indicator:checked {
            background: #22C55E;
            border: 1px solid #16A34A;
        }

        QSpinBox {
            background-color: #0F1720;
            color: #E6EDF3;
            border: 1px solid #223041;
            border-radius: 10px;
            padding: 6px 10px;
        }
        QSpinBox:focus { border: 1px solid #3B82F6; }
        QSpinBox::up-button, QSpinBox::down-button {
            width: 18px; border: none; background: transparent;
        }

        /* Buttons */
        QPushButton {
            background-color: #111827;
            color: #E6EDF3;
            border: 1px solid #223041;
            border-radius: 12px;
            padding: 10px 12px;
            font-weight: 600;
        }
        QPushButton:hover { background-color: #162233; border: 1px solid #2B3F58; }
        QPushButton:pressed { background-color: #0F1720; }

        /* Cards / Panels */
        QGroupBox {
            background-color: #0F1720;
            border: 1px solid #223041;
            border-radius: 14px;
            margin-top: 14px;
            padding: 12px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 12px;
            top: -2px;
            padding: 0 8px;
            color: #93C5FD;              /* ✅ titre visible (plus noir) */
            background-color: #0B0F14;    /* ✅ évite “bande noire invisible” */
            font-weight: 700;
        }

        QTextEdit {
            background-color: #0F1720;
            color: #E6EDF3;
            border: 1px solid #223041;
            border-radius: 14px;
            padding: 10px;
            font-family: Consolas;
            font-size: 11px;
        }
        """)

    def choose_folder(self) -> None:
        folder = QtWidgets.QFileDialog.getExistingDirectory(self, "Choisir un dossier", str(Path('.').resolve()))
        if folder:
            self.path_edit.setText(folder)

    def run_scan(self) -> None:
        root = Path(self.path_edit.text())
        scan_ports = self.ports_cb.isChecked()
        scan_env = self.env_cb.isChecked()
        # run scanning (may take time) in same thread for simplicity; can use threading if desired
        self.scanner.run(root, scan_ports, scan_env)
        # update score badge
        score = self.scanner.score
        if score < 20:
            color = "#2E7D32"; level = "LOW"
        elif score < 50:
            color = "#FF8F00"; level = "MEDIUM"
        else:
            color = "#C62828"; level = "HIGH"
        self.score_badge.setText(f"Attack Surface Score: {score} ({level})")
        self.score_badge.setStyleSheet(f"""
        background-color:{color};
        color:#0B0F14;
        padding:12px;
        font-size:18px;
        font-weight:800;
        border-radius:16px;
        """)
        risky_count = sum(1 for l in self.scanner.listeners if l.get("risks"))
        secrets_count = sum(len(e.get("secrets", [])) for e in self.scanner.env_files)
        self.kpi_label.setText(f"Risky ports: {risky_count}   •   Secrets: {secrets_count}")
        # update details
        text_lines = []
        text_lines.append("Listening services:")
        if self.scanner.listeners:
            for l in self.scanner.listeners:
                risks = ", ".join(l['risks']) if l['risks'] else "none"
                text_lines.append(f"- {l['ip']}:{l['port']} ({l['service'] or 'unknown'}) → {risks}")
        else:
            text_lines.append("- (scan des ports désactivé ou aucun port)")
        text_lines.append("")
        text_lines.append("Environment secrets:")
        if self.scanner.env_files:
            for env in self.scanner.env_files:
                text_lines.append(f"- {env['path']} : {len(env['secrets'])} clés sensibles")
        else:
            text_lines.append("- (aucun secret ou scan .env désactivé)")
        text_lines.append("")
        text_lines.append("Suggestions:")
        if self.scanner.suggestions:
            for sug in self.scanner.suggestions:
                text_lines.append(f"• {sug}")
        else:
            text_lines.append("• Votre surface d’attaque est propre !")
        self.details_text.setPlainText("\n".join(text_lines))
        # draw graph
        self.graph_view.draw_graph(
            self.scanner,
            show_safe=self.show_safe_cb.isChecked(),
            show_processes=self.show_proc_cb.isChecked(),
            max_ports=int(self.max_ports_spin.value()),
        )



    def on_node_clicked(self, payload: dict) -> None:
        # Replace details with focused info (keeps UI clean)
        lines = []
        t = payload.get("type", "node")
        if t in ("port_risky", "port_safe"):
            lines.append(f"Port: {payload.get('ip')}:{payload.get('port')}")
            lines.append(f"Service: {payload.get('service')}")
            lines.append(f"Process: {payload.get('process') or 'unknown'}")
            risks = payload.get("risks") or []
            lines.append("Risks: " + (", ".join(risks) if risks else "none"))
        elif t == "env_file":
            lines.append(f"Env file: {payload.get('path')}")
            secs = payload.get("secrets") or []
            lines.append(f"Sensitive keys: {len(secs)}")
            for s in secs[:30]:
                lines.append(f" - {s}")
        elif t == "env_cluster":
            lines.append(f".env findings: {payload.get('count')}")
        elif t == "process":
            lines.append(f"Process: {payload.get('process')}")
        else:
            lines.append(str(payload))
        self.details_text.setPlainText("\n".join(lines))

def main() -> None:
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()