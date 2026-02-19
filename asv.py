#!/usr/bin/env python3

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import psutil  # type: ignore

# Map well known ports to service names.  This list is deliberately
# non‑exhaustive: unknown ports will simply show their port number.
SERVICE_PORTS: Dict[int, str] = {
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
    6379: "Redis",
    1521: "OracleDB",
    19000: "ElasticSearch",
}

# Keys that might indicate secrets when scanning env files.  Matching is
# case‑insensitive and applied to both keys and values.
SECRET_KEYWORDS = [
    "secret", "token", "password", "key", "access_key", "private_key",
    "api_key", "auth", "credential", "passphrase"
]


@dataclass
class Listener:
    ip: str
    port: int
    pid: Optional[int]
    process: Optional[str]
    service: Optional[str]
    risks: List[str] = field(default_factory=list)

    def to_node(self, host_id: str) -> List[Dict[str, object]]:
        """Return node and edge definitions for vis‑network."""
        nodes = []
        edges = []
        node_id = f"port_{self.port}_{self.ip.replace('.', '_').replace(':', '_')}"
        label = f"{self.port}"
        if self.service:
            label += f"\n{self.service}"
        nodes.append({
            "id": node_id,
            "label": label,
            "shape": "box",
            "color": {
                "background": "#006064",  # teal dark
                "border": "#0097A7",
                "highlight": {
                    "background": "#00838F",
                    "border": "#00ACC1"
                }
            },
            "font": {"color": "#ECEFF1"},
        })
        # Edge from host to port
        edges.append({"from": host_id, "to": node_id, "arrows": "to"})
        # Add process node if known
        if self.process:
            proc_id = f"proc_{self.pid}" if self.pid is not None else f"proc_{self.process}"
            nodes.append({
                "id": proc_id,
                "label": self.process,
                "shape": "ellipse",
                "color": {
                    "background": "#4527A0",  # deep purple
                    "border": "#673AB7",
                    "highlight": {
                        "background": "#512DA8",
                        "border": "#7E57C2"
                    }
                },
                "font": {"color": "#EDE7F6"},
            })
            edges.append({"from": node_id, "to": proc_id, "arrows": "to"})
        # Risk nodes
        for idx, risk in enumerate(self.risks):
            risk_id = f"risk_{node_id}_{idx}"
            nodes.append({
                "id": risk_id,
                "label": risk,
                "shape": "dot",
                "color": {
                    "background": "#B71C1C",  # dark red
                    "border": "#D32F2F",
                    "highlight": {
                        "background": "#C62828",
                        "border": "#E53935"
                    }
                },
                "font": {"color": "#FFEBEE", "size": 12},
                "size": 12
            })
            edges.append({"from": node_id, "to": risk_id, "arrows": "to"})
        return nodes + edges  # type: ignore


def discover_listeners() -> List[Listener]:
    """Discover listening sockets using psutil and return a list of Listener objects."""
    listeners: List[Listener] = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status != psutil.CONN_LISTEN:
                continue
            try:
                local_addr = conn.laddr
                # psutil returns a sockaddr tuple (ip, port) on some platforms
                if hasattr(local_addr, 'ip') and hasattr(local_addr, 'port'):
                    ip = local_addr.ip
                    port = local_addr.port
                else:
                    ip, port = local_addr
            except Exception:
                continue
            pid = conn.pid
            process_name: Optional[str] = None
            if pid is not None:
                try:
                    process_name = psutil.Process(pid).name()
                except Exception:
                    process_name = None
            service = SERVICE_PORTS.get(port)
            risks: List[str] = []
            # risk rules
            if ip in ("0.0.0.0", "::"):
                # Exposed to all interfaces
                if port in (3306, 5432, 27017, 6379, 11211, 1521, 19000):
                    risks.append("Exposed database/service")
                elif port in (22,):
                    risks.append("Exposed SSH service")
                elif port in (80, 443):
                    risks.append("Public web service")
                else:
                    risks.append("Publicly exposed port")
            listeners.append(Listener(ip=ip, port=port, pid=pid,
                                       process=process_name, service=service,
                                       risks=risks))
    except Exception as e:
        print(f"Error enumerating network connections: {e}", file=sys.stderr)
    return listeners


def scan_env_files(base_path: Path) -> List[Dict[str, object]]:
    """Recursively scan for `.env*` files under base_path and detect potential secrets."""
    env_results: List[Dict[str, object]] = []
    for root, _, files in os.walk(base_path):
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
                                exposures.append({
                                    'key': key.strip(),
                                    'line': line.strip(),
                                })
                except Exception:
                    continue
                if exposures:
                    env_results.append({
                        'path': str(fpath),
                        'secrets': exposures
                    })
    return env_results


def build_report(path: Path) -> Dict[str, object]:
    """Run discovery routines and build a structured report dictionary."""
    host_info = {
        'hostname': os.uname().nodename if hasattr(os, 'uname') else None,
        'os': os.name,
        'scan_time': datetime.utcnow().isoformat() + 'Z',
    }
    listeners = discover_listeners()
    env_files = scan_env_files(path)
    return {
        'host': host_info,
        'listeners': [asdict(l) for l in listeners],
        'env_files': env_files,
    }


def generate_summary(report: Dict[str, object]) -> str:
    """Generate a human readable summary text from the report."""
    lines: List[str] = []
    listeners: List[Dict[str, object]] = report.get('listeners', [])  # type: ignore
    env_files: List[Dict[str, object]] = report.get('env_files', [])  # type: ignore
    lines.append(f"Host: {report['host'].get('hostname', 'unknown')} ({report['host'].get('os')})")
    lines.append(f"Scan time (UTC): {report['host'].get('scan_time')}")
    lines.append('')
    lines.append(f"Listening services: {len(listeners)} found")
    for l in listeners:
        port = l['port']
        ip = l['ip']
        proc = l['process'] or 'unknown'
        svc = l['service'] or 'unknown'
        risk_str = ', '.join(l['risks']) if l['risks'] else 'none'
        lines.append(f"  • {ip}:{port} ({svc}) – proc: {proc}, risks: {risk_str}")
    lines.append('')
    lines.append(f"Environment files with potential secrets: {len(env_files)} found")
    for env in env_files:
        lines.append(f"  • {env['path']}: {len(env['secrets'])} potential secret lines")
    return '\n'.join(lines)


def generate_html(report: Dict[str, object], html_path: Path) -> None:
    """Generate a dark themed interactive HTML report using vis‑network."""
    # Build nodes and edges from listeners and env data
    nodes: List[Dict[str, object]] = []
    edges: List[Dict[str, object]] = []
    host_id = "host_node"
    nodes.append({
        "id": host_id,
        "label": report['host'].get('hostname', 'host'),
        "shape": "box",
        "color": {
            "background": "#004D40",  # teal dark
            "border": "#00796B",
            "highlight": {
                "background": "#00695C",
                "border": "#00897B"
            }
        },
        "font": {"color": "#E0F2F1", "size": 20},
    })
    # Listeners
    for lst in report['listeners']:
        l = Listener(**lst)
        ne = l.to_node(host_id)
        # to_node returns a combined list of nodes and edges; separate them
        for item in ne:
            # Distinguish edges by presence of 'from'
            if 'from' in item:
                edges.append(item)
            else:
                nodes.append(item)
    # Environment file nodes
    envs = report.get('env_files', [])
    for idx, env in enumerate(envs):
        env_id = f"env_{idx}"
        nodes.append({
            "id": env_id,
            "label": Path(env['path']).name,
            "shape": "file",
            "color": {
                "background": "#37474F",  # blue grey
                "border": "#455A64",
                "highlight": {
                    "background": "#455A64",
                    "border": "#607D8B"
                }
            },
            "font": {"color": "#ECEFF1"},
        })
        edges.append({"from": host_id, "to": env_id, "arrows": "to"})
        # Add secret nodes
        for s_idx, secret in enumerate(env['secrets']):
            sec_id = f"secret_{idx}_{s_idx}"
            nodes.append({
                "id": sec_id,
                "label": secret['key'],
                "shape": "triangle",
                "color": {
                    "background": "#827717",  # olive
                    "border": "#9E9D24",
                    "highlight": {
                        "background": "#9E9D24",
                        "border": "#C0CA33"
                    }
                },
                "font": {"color": "#FFF8E1", "size": 12},
            })
            edges.append({"from": env_id, "to": sec_id, "arrows": "to"})

    # Assemble HTML content
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Attack Surface Report</title>
  <script src="https://unpkg.com/vis-network@10.0.2/dist/vis-network.min.js"></script>
  <link href="https://unpkg.com/vis-network@10.0.2/dist/vis-network.min.css" rel="stylesheet" type="text/css" />
  <style>
    body {{
      background-color: #121212;
      color: #ECEFF1;
      font-family: Arial, Helvetica, sans-serif;
      margin: 0;
      padding: 0;
    }}
    #network {{
      width: 100%;
      height: 80vh;
      border: none;
    }}
    h1 {{
      text-align: center;
      padding: 1rem;
      margin: 0;
      font-weight: normal;
      font-size: 1.5rem;
      background: #263238;
    }}
    .summary {{
      padding: 1rem;
      background: #1E282C;
      border-top: 1px solid #37474F;
      font-size: 0.9rem;
      line-height: 1.4;
    }}
    .summary pre {{
      white-space: pre-wrap;
      word-break: break-word;
    }}
  </style>
</head>
<body>
  <h1>Attack Surface Report</h1>
  <div id="network"></div>
  <div class="summary">
    <h2>Summary</h2>
    <pre>{generate_summary(report)}</pre>
  </div>
  <script>
    // Data for the network
    var nodes = new vis.DataSet({json.dumps(nodes)});
    var edges = new vis.DataSet({json.dumps(edges)});
    var container = document.getElementById('network');
    var data = {{ nodes: nodes, edges: edges }};
    var options = {{
      autoResize: true,
      nodes: {{
        borderWidth: 1,
        shadow: true
      }},
      edges: {{
        color: {{ color: '#546E7A' }},
        arrows: {{ to: {{ enabled: true, scaleFactor: 0.5 }} }},
        smooth: {{ type: 'cubicBezier', roundness: 0.4 }}
      }},
      layout: {{
        improvedLayout: true
      }},
      physics: {{
        stabilization: {{ iterations: 150 }},
        barnesHut: {{
          gravitationalConstant: -4000,
          springLength: 150
        }}
      }}
    }};
    var network = new vis.Network(container, data, options);
  </script>
</body>
</html>"""
    # Write file
    with open(html_path, 'w', encoding='utf-8') as out:
        out.write(html_content)


def save_json(data: Dict[str, object], path: Path) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)


def save_summary(summary: str, path: Path) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        f.write(summary)


def cmd_scan(args: argparse.Namespace) -> None:
    target_path = Path(args.path).resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    report = build_report(target_path)
    if args.json or (not args.json and not args.html):
        json_path = out_dir / 'report.json'
        save_json(report, json_path)
    summary_text = generate_summary(report)
    save_summary(summary_text, out_dir / 'summary.txt')
    if args.html:
        html_path = out_dir / 'report.html'
        generate_html(report, html_path)
    elif not args.json:
        # If no format specified, produce both
        save_json(report, out_dir / 'report.json')
        html_path = out_dir / 'report.html'
        generate_html(report, html_path)
    print(f"Scan complete. Reports written to {out_dir}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Attack Surface Visualizer (ASV)")
    subparsers = parser.add_subparsers(dest='command', required=True)
    scan = subparsers.add_parser('scan', help='Run a scan of the local attack surface')
    scan.add_argument('--path', default='.', help='Directory to scan for environment files (default: current directory)')
    scan.add_argument('--out', default='report', help='Directory to write output files (default: ./report)')
    scan.add_argument('--json', action='store_true', help='Generate only JSON output (report.json)')
    scan.add_argument('--html', action='store_true', help='Generate only HTML output (report.html)')
    scan.set_defaults(func=cmd_scan)
    return parser


def main(argv: List[str] = None) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == '__main__':
    main()