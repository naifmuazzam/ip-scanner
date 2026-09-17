# IP Scanner

A lightweight Python GUI tool to scan IP addresses and identify available vs used hosts on your network.

## Features

- **Simple GUI** — Clean tkinter interface, no external dependencies
- **Flexible Input** — CIDR (`192.168.1.0/24`), range (`192.168.1.1-50`), or single IP
- **Multi-threaded** — Configurable thread count for fast scanning
- **Fast Mode** — One-click preset for speed (250ms timeout, 254 threads)
- **Hostname Resolution** — Optional reverse DNS lookup for used IPs
- **CSV Export** — Save scan results to file
- **Auto-Detect Subnet** — Suggests your local network on startup
- **Cross-Platform** — Works on Windows, Linux, and macOS

## Requirements

- Python 3.6+
- No pip install needed — uses only standard library (`tkinter`)

## Usage

```bash
python ip_scanner_gui.py
```

1. Enter a network/range (e.g. `192.168.1.0/24`)
2. Adjust timeout and threads if needed
3. Click **Start Scan**
4. Results appear in real-time — green = used, light = available
5. Optionally export to CSV

## How It Works

Each IP is pinged once using system `ping` command. Hosts that respond are marked as **Used**; others are **Available**. Hostname resolution (optional) performs reverse DNS on used IPs only.

## License

MIT
