# Attack Surface Visualizer (ASV)

ASV is a lightweight security helper that gives developers an at‑a‑glance view of the services
exposed on their local machine as well as any secrets that might be lurking in
`.env` files.  It is designed for quick, one‑off scans during development or at
hackathons when you need a rough idea of your attack surface without deploying
heavyweight scanners or sending your code to a cloud service.

## Features

* **Cross‑platform port discovery** – ASV uses the [psutil](https://pypi.org/project/psutil/)
  library to find listening TCP/UDP sockets on Linux, macOS and Windows.  It
  identifies the process bound to each port and matches common port numbers to
  well known services (HTTP, SSH, PostgreSQL, Redis, etc.).
* **Exposed service detection** – ports bound to `0.0.0.0` or `::` are marked
  as publicly exposed.  If a database or sensitive service is bound to an
  exposed address a high‑severity warning is raised.
* **Environment file scanning** – ASV scans the target directory for `.env` files
  and highlights any lines where the key or value look like they may contain
  secrets (`key`, `secret`, `token`, `password`, etc.).  The actual values are
  not displayed in the report.
* **Dark, interactive report** – the tool generates a standalone HTML report
  featuring a network graph.  The graph shows your host at the centre with
  service ports, detected technologies and risk nodes radiating outward.  It
  uses the open source [vis‑network](https://visjs.github.io/vis-network/) library
  loaded from a CDN and is styled with a dark theme.
* **JSON output** – a machine readable report is also emitted for further
  automation or integration with other tools.

## Installation

ASV is implemented in a single Python file with minimal dependencies.  You
should create a virtual environment and install the required packages:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

To scan the current working directory and generate a report in `./report`:

```bash
python asv.py scan --out ./report
```

You can specify a different directory to scan with `--path` and choose to
output only JSON (`--json`) or HTML (`--html`).  Run the tool with `--help`
for a list of all options.

After running `scan` you will find:

* `report.json` – the raw results of the scan.
* `report.html` – a pretty, interactive network graph with a dark theme.
* `summary.txt` – a concise plain‑text summary of the findings.

## Graphical application

For those who prefer a desktop application over a web report, two GUI
implementations are provided:

* **Classic Tkinter GUI (`asv_gui.py`)** – a lightweight interface based on
  Tkinter.  It scans the current working directory by default and displays an
  attack surface score, a simple graph and a summary of findings.  You can
  adjust the scanned path by editing the `path` variable near the bottom of
  `asv_gui.py`.

* **Modern PyQt GUI (`asv_gui_modern.py`)** – a polished application built
  with PyQt5.  It offers a dark, modern interface with folder selection, toggle
  options to enable/disable port and env scanning, a zoomable network graph
  and detailed suggestions.  Use this version for the best experience.

### Running the classic Tkinter GUI

```bash
python asv_gui.py
```

### Running the modern PyQt GUI

```bash
python asv_gui_modern.py
```

Both GUIs compute an attack surface score, draw a network diagram and list
suggestions to reduce your exposure.  You may need to install additional
packages for the PyQt version:

```bash
pip install psutil networkx numpy Pillow PyQt5
```

The Tkinter GUI depends only on psutil, networkx and Pillow.

## License

This project is released under the MIT license.  See [LICENSE](LICENSE)
for details.