#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, scrolledtext
import psutil  # type: ignore
import os
import sys
import re
import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import networkx as nx  # type: ignore


# Service and risk definitions similar to CLI
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


class ASVScanner:
    """Performs scanning operations and computes risk scores."""

    def __init__(self, path: Path):
        self.path = path
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
            proc_name = None
            if pid is not None:
                try:
                    proc_name = psutil.Process(pid).name()
                except Exception:
                    proc_name = None
            service = SERVICE_PORTS.get(port)
            # Determine risk level
            risks: List[str] = []
            internal_ips = ["127.0.0.1", "::1"] + [iface.address for iface in psutil.net_if_addrs().values() for iface in iface]
            # Exposed if binds to all interfaces (0.0.0.0) or unspecified IPv6 ::
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

    def scan_env_files(self) -> None:
        results = []
        for root, _, files in os.walk(self.path):
            for fname in files:
                if fname.startswith('.env'):
                    fpath = Path(root) / fname
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

    def compute_score(self) -> None:
        # Basic scoring: each exposed DB port +20, exposed other +10, secret exposures +5
        score = 0
        for l in self.listeners:
            if l['risks']:
                if any(r.startswith('Public DB') for r in l['risks']):
                    score += 20
                else:
                    score += 10
        for env in self.env_files:
            score += len(env['secrets']) * 5
        self.score = score

    def generate_suggestions(self) -> None:
        suggestions = []
        for l in self.listeners:
            ip = l['ip']
            port = l['port']
            if not l['risks']:
                continue
            for risk in l['risks']:
                if "DB" in risk:
                    suggestions.append(f"Restrict database port {port} to localhost")
                elif "SSH" in risk:
                    suggestions.append("Limit SSH to local network or change port")
                elif "Web" in risk:
                    suggestions.append("Ensure web service uses TLS and is behind a reverse proxy")
                else:
                    suggestions.append(f"Close or firewall port {port} if not needed")
        if not suggestions:
            suggestions.append("No critical issues detected. Keep your system patched!")
        # Remove duplicates and take top 5
        self.suggestions = list(dict.fromkeys(suggestions))[:5]

    def run(self) -> None:
        self.discover_listeners()
        self.scan_env_files()
        self.compute_score()
        self.generate_suggestions()


class ASVApp(tk.Tk):
    """Tkinter application showing the attack surface."""

    def __init__(self, scanner: ASVScanner):
        super().__init__()
        self.scanner = scanner
        self.title("Attack Surface Visualizer")
        self.configure(bg="#121212")
        self.geometry("1000x700")
        self.resizable(True, True)
        # Header with score
        self.header = tk.Frame(self, bg="#263238")
        self.header.pack(fill=tk.X, side=tk.TOP)
        self.score_label = tk.Label(self.header, text="", font=("Segoe UI", 20, "bold"), fg="#ECEFF1", bg="#263238")
        self.score_label.pack(side=tk.LEFT, padx=20, pady=10)
        # Content area
        self.content = tk.Frame(self, bg="#121212")
        self.content.pack(fill=tk.BOTH, expand=True)
        # Canvas for graph
        self.canvas = tk.Canvas(self.content, bg="#1E282C", highlightthickness=0)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        # Sidebar for details
        self.sidebar = tk.Frame(self.content, bg="#263238", width=300)
        self.sidebar.pack(side=tk.RIGHT, fill=tk.Y)
        # Scrolled text for suggestions and details
        self.details = scrolledtext.ScrolledText(self.sidebar, wrap=tk.WORD, fg="#ECEFF1", bg="#37474F", insertbackground="#ECEFF1", borderwidth=0, relief=tk.FLAT)
        self.details.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        # Kick off scan in separate thread
        threading.Thread(target=self.run_scan, daemon=True).start()

    def run_scan(self) -> None:
        self.scanner.run()
        self.after(0, self.update_ui)

    def update_ui(self) -> None:
        # Update score label and badge color
        score = self.scanner.score
        if score < 20:
            badge_color = "#2E7D32"  # green
            level = "LOW"
        elif score < 50:
            badge_color = "#FF8F00"  # amber
            level = "MEDIUM"
        else:
            badge_color = "#C62828"  # red
            level = "HIGH"
        self.header.configure(bg=badge_color)
        self.score_label.configure(bg=badge_color, text=f"ATTACK SURFACE SCORE: {score} ({level})")
        # Populate details text
        summary_lines = []
        summary_lines.append(f"Scan time: {datetime.utcnow().isoformat()}Z")
        summary_lines.append("")
        summary_lines.append("Listening services:")
        for l in self.scanner.listeners:
            risks = ", ".join(l['risks']) if l['risks'] else "none"
            summary_lines.append(f"- {l['ip']}:{l['port']} ({l['service'] or 'unknown'}) → {risks}")
        summary_lines.append("")
        summary_lines.append("Environment secrets:")
        if self.scanner.env_files:
            for env in self.scanner.env_files:
                summary_lines.append(f"- {env['path']}: {len(env['secrets'])} potential secrets")
        else:
            summary_lines.append("- None")
        summary_lines.append("")
        summary_lines.append("Top suggestions:")
        for s in self.scanner.suggestions:
            summary_lines.append(f"• {s}")
        self.details.delete('1.0', tk.END)
        self.details.insert(tk.END, "\n".join(summary_lines))
        self.details.configure(state=tk.DISABLED)
        # Draw graph
        self.draw_graph()

    def draw_graph(self) -> None:
        G = nx.DiGraph()
        host_id = "HOST"
        G.add_node(host_id, label=self.scanner.path.name or "host")
        # Add listener nodes
        for idx, l in enumerate(self.scanner.listeners):
            node_id = f"L{idx}"
            label = f"{l['port']}\n{l['service'] or 'unknown'}"
            color = "#0097A7" if not l['risks'] else "#D32F2F"
            G.add_node(node_id, label=label, color=color)
            G.add_edge(host_id, node_id)
            # Process node
            if l['process']:
                proc_id = f"P{idx}"
                G.add_node(proc_id, label=l['process'], color="#512DA8")
                G.add_edge(node_id, proc_id)
            # Risk nodes
            for ridx, risk in enumerate(l['risks']):
                risk_id = f"R{idx}_{ridx}"
                G.add_node(risk_id, label=risk, color="#C62828")
                G.add_edge(node_id, risk_id)
        # Env nodes
        for eidx, env in enumerate(self.scanner.env_files):
            env_id = f"E{eidx}"
            G.add_node(env_id, label=Path(env['path']).name, color="#455A64")
            G.add_edge(host_id, env_id)
            for sidx, secret in enumerate(env['secrets']):
                s_id = f"S{eidx}_{sidx}"
                G.add_node(s_id, label=secret['key'], color="#9E9D24")
                G.add_edge(env_id, s_id)
        # Compute positions
        pos = nx.spring_layout(G, k=1.5, iterations=100)
        # Normalise positions to canvas size
        width = self.canvas.winfo_width() or self.canvas.winfo_reqwidth()
        height = self.canvas.winfo_height() or self.canvas.winfo_reqheight()
        # Clear canvas
        self.canvas.delete('all')
        # Scale positions
        # Get min/max coords
        xs = [p[0] for p in pos.values()]
        ys = [p[1] for p in pos.values()]
        min_x, max_x = min(xs), max(xs)
        min_y, max_y = min(ys), max(ys)
        def scale(x, min_v, max_v, max_size, padding=60):
            if max_v - min_v == 0:
                return max_size / 2
            return padding + (x - min_v) / (max_v - min_v) * (max_size - 2 * padding)
        # Draw edges first
        for u, v in G.edges():
            x1 = scale(pos[u][0], min_x, max_x, width)
            y1 = scale(pos[u][1], min_y, max_y, height)
            x2 = scale(pos[v][0], min_x, max_x, width)
            y2 = scale(pos[v][1], min_y, max_y, height)
            self.canvas.create_line(x1, y1, x2, y2, fill="#546E7A")
        # Draw nodes
        for node_id, attrs in G.nodes(data=True):
            x = scale(pos[node_id][0], min_x, max_x, width)
            y = scale(pos[node_id][1], min_y, max_y, height)
            r = 20
            fill = attrs.get('color', '#37474F')
            text = attrs.get('label', node_id)
            self.canvas.create_oval(x-r, y-r, x+r, y+r, fill=fill, outline=fill)
            self.canvas.create_text(x, y, text=text, fill="#ECEFF1", font=("Segoe UI", 8), justify=tk.CENTER)


def main() -> None:
    path = Path('.')
    scanner = ASVScanner(path)
    app = ASVApp(scanner)
    app.mainloop()


if __name__ == '__main__':
    main()