# 🛡️ PyNIDS

### A single-file Python Network Intrusion Detection System — deploy in 30 seconds, understand in 30 minutes.

[![Python](https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS-lightgrey)]()
[![Dependencies](https://img.shields.io/badge/deps-scapy%20%7C%20flask-orange)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Maintenance](https://img.shields.io/badge/maintained-yes-success)]()

**PyNIDS** is a self-contained intrusion detection system in a single Python file. It captures live traffic, runs stateful and signature-based detection, automatically blocks offending IPs via `iptables`, and ships with a real-time web dashboard — all without a build step, a service mesh, or a 400 MB ELK stack.

```bash
pip install scapy flask
sudo python3 pynids.py sniff -i eth0
```

That's it. That's the install.

---

## 📖 Table of Contents

- [Why PyNIDS?](#-why-pynids)
- [Features](#-features)
- [Screenshots](#-screenshots)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
  - [Live Capture](#live-capture)
  - [PCAP Replay](#pcap-replay)
  - [Dashboard](#dashboard)
  - [Suricata Integration](#suricata-integration)
- [Detection Rules](#-detection-rules)
  - [Signature Rules](#signature-rules)
  - [Stateful Detectors](#stateful-detectors)
- [Automated Response](#-automated-response)
- [Architecture](#-architecture)
- [Configuration](#-configuration)
- [Testing Detections](#-testing-detections)
- [Roadmap](#-roadmap)
- [Limitations](#-limitations)
- [FAQ](#-faq)
- [Contributing](#-contributing)
- [License](#-license)

---

## 💡 Why PyNIDS?

| | Suricata / Snort | **PyNIDS** |
| :--- | :---: | :---: |
| Install time | Minutes to hours | **30 seconds** |
| Config complexity | YAML + Lua + rule syntax | **One JSON file** |
| Code size | ~500k lines of C | **~1,200 lines of Python** |
| Extensibility | C modules, Lua | **Edit a dict, restart** |
| Throughput | 10+ Gbps | ~100 Mbps |
| Learning curve | Steep | **Flat** |

**PyNIDS is not a Suricata replacement.** It's for:

- 🧪 **Home labs** and CTF environments
- 🎓 **Teaching** network security concepts with readable code
- 🔧 **Custom detections** that are awkward to express in Suricata rule syntax
- 🧩 **Prototyping** new heuristics before porting them to C
- 📊 **Enriching** Suricata output with Python-side logic (see [`parse-eve`](#suricata-integration))

If you need line-rate IDS on a 40G backbone, use Suricata. If you want to understand *how* an IDS works and customize it in an afternoon, use PyNIDS.

---

## ✨ Features

### 🔍 Detection
- **Signature engine** — regex rules declared in JSON, no recompile needed
- **Stateful detectors** — sliding-window analysis for:
  - TCP port scans (distinct destination ports per source)
  - SYN floods (rate-based)
  - ICMP floods
  - SSH brute force (connection attempts to port 22)
  - DNS floods (query rate to port 53)
- **DNS blacklist** — alert on queries for known-bad domains (suffix-matched)
- **IP blacklist** — alert on traffic from known-bad hosts
- **Per-rule cooldowns** — quiet noisy rules, keep critical ones loud

### 🛡️ Response
- **Automatic `iptables` blocking** with configurable TTL
- **Whitelist + home-net safety rails** — never blocks your own infrastructure
- **Persistent block state** — survives restarts without orphaning rules
- **Opt-in flush on exit** — keep your blocks when you Ctrl+C, or clean up

### 📊 Observability
- **Built-in Flask dashboard** with Chart.js visualizations
- **JSON-lines alert log** with automatic size-based rotation
- **Live stats loop** — packets, alerts, active blocks
- **Unified schema** — merges Suricata alerts via `parse-eve`

### 🧰 Engineering
- **Single file** — `scp` it, review it, audit it
- **Frozen dataclass config** — no accidental cross-process mutation
- **Bounded memory** — sliding windows cap retained events
- **Tight exception handling** — no `except Exception: pass` landmines

---

## 📸 Screenshots

> **Dashboard** — real-time alert timeline, top signatures, top sources, and a live alert table.

```
┌─────────────────────────────────────────────────────────────────┐
│  🛡️ PyNIDS — Threat Dashboard           Auto-refresh 10s · 42   │
├──────────────┬──────────────┬──────────────┬────────────────────┤
│ 42           │ 11           │ 24           │ 7                  │
│ TOTAL ALERTS │ HIGH         │ MEDIUM       │ IPs BLOCKED        │
├──────────────┴──────────────┴──────────────┴────────────────────┤
│  Alert Timeline (per minute)                                    │
│  ▁▁▂▃▅▆▇▇▆▅▃▂▁▁▂▄▆█▆▄▂▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁   │
├──────────────────────────────┬──────────────────────────────────┤
│  Top Signatures              │  Top Sources                     │
│  PORT_SCAN        ████████   │  203.0.113.66      █████████     │
│  SSH_BRUTE        ██████     │  198.51.100.42     ██████        │
│  SYN_FLOOD        ████       │  192.0.2.99        ████          │
└──────────────────────────────┴──────────────────────────────────┘
```

> **Console output** during a scan:

```console
2025-01-15 14:32:11 WARNING  pynids.detector    [SEV2] PORT_SCAN | 203.0.113.66 -> 10.0.0.5 | TCP port scan: 47 ports in 10s [BLOCKED]
2025-01-15 14:32:11 WARNING  pynids.responder   BLOCKED 203.0.113.66 for 3600s — PORT_SCAN: TCP port scan: 47 ports in 10s
2025-01-15 14:32:14 WARNING  pynids.detector    [SEV1] SQLI-001 | 203.0.113.66 -> 10.0.0.5 | SQL Injection pattern in payload
2025-01-15 14:32:41 INFO     pynids.stats       packets=18422 alerts=3 blocked=1 active_blocks=1
```

---

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install scapy flask

# 2. Clone
git clone https://github.com/yourusername/pynids.git
cd pynids

# 3. Initialize config files (creates /var/log/pynids/)
sudo python3 pynids.py init

# 4. Start sniffing
sudo python3 pynids.py sniff -i eth0

# 5. In another terminal, launch the dashboard
python3 pynids.py dashboard
# → http://localhost:5000
```

**Trigger a test alert** from another machine:

```bash
nmap -sS -p 1-100 <your-pynids-host>
```

Watch the console light up and the dashboard populate in real time.

---

## 📦 Installation

### Requirements

- Python **3.9+**
- Linux or macOS (Windows requires WSL2 or Npcap)
- `root`/`sudo` for raw socket capture and `iptables`

### Dependencies

```bash
pip install scapy flask
```

That's the entire dependency tree. No C compiler, no kernel headers, no `libpcap-dev`.

### Optional: rootless capture

Grant `python3` the capabilities it needs instead of running everything as root:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```

> ⚠️ This grants capability to **every** Python script. Only do this on a machine you control.

---

## 🎮 Usage

### Live Capture

```bash
# Basic live capture on eth0
sudo python3 pynids.py sniff -i eth0

# Detect-only — never touch iptables
sudo python3 pynids.py sniff -i eth0 --no-block

# Custom BPF filter — only inspect HTTP/HTTPS
sudo python3 pynids.py sniff -i eth0 -f "tcp port 80 or tcp port 443"

# Verbose debug logging
sudo python3 pynids.py sniff -i eth0 -v

# Clean up iptables rules on exit (default: leave them installed)
sudo python3 pynids.py sniff -i eth0 --flush-on-exit
```

### PCAP Replay

Replay a capture through the full detection pipeline — perfect for testing rules against known-bad traffic:

```bash
sudo python3 pynids.py sniff -r suspicious.pcap
sudo python3 pynids.py sniff -r ../samples/sqlmap-attack.pcap -v
```

The responder runs in dry-run mode during replay (`[DRY-RUN] would block ...`) so you don't firewall yourself while testing.

### Dashboard

```bash
# Local only (default)
python3 pynids.py dashboard

# Custom host/port
python3 pynids.py dashboard --host 0.0.0.0 --port 8080
```

> ⚠️ The dashboard has **no authentication**. Do not expose it to the public internet. If you must bind it to `0.0.0.0`, put it behind a reverse proxy with auth.

**API endpoints** (useful for your own integrations):

| Endpoint | Returns |
| :--- | :--- |
| `GET /` | Full HTML dashboard |
| `GET /api/stats` | Aggregated stats (JSON) |
| `GET /api/alerts` | Last 200 alerts (JSON) |

### Suricata Integration

Running Suricata and PyNIDS side-by-side? Merge both alert streams into one dashboard:

```bash
# In one terminal — tail Suricata's EVE log
python3 pynids.py parse-eve -f /var/log/suricata/eve.json

# The dashboard now shows both pynids-* and SRC-* rules
python3 pynids.py dashboard
```

`parse-eve` normalizes Suricata's alert format into PyNIDS's unified schema, so `SRC-2010935` (an ET rule) and `PORT_SCAN` (a local detector) show up side by side.

---

## 📋 Detection Rules

### Signature Rules

Rules are declarative JSON. Edit `/var/log/pynids/rules.json` and restart the sniffer:

```json
{
  "rules": [
    {
      "id": "SQLI-001",
      "msg": "SQL Injection pattern in payload",
      "protocol": "tcp",
      "dst_port": [80, 443, 8080, 8443],
      "regex": "(?i)(union[\\s/+]+select|or\\s+1\\s*=\\s*1|'\\s*or\\s*')",
      "severity": 1,
      "action": "block",
      "cooldown": 30
    }
  ]
}
```

**Field reference:**

| Field | Required | Description |
| :--- | :---: | :--- |
| `id` | ✅ | Unique rule identifier (shown in alerts) |
| `msg` | ✅ | Human-readable description |
| `severity` | ✅ | `1` (high), `2` (medium), `3` (low) |
| `action` | ✅ | `alert` or `block` (block triggers iptables) |
| `protocol` | ⬜ | `tcp`, `udp`, or omit for any |
| `dst_port` | ⬜ | Integer, list, or `null` for any |
| `regex` | ⬜ | Python regex matched against payload bytes |
| `cooldown` | ⬜ | Per-rule cooldown in seconds (overrides global) |

The default ruleset ships with detection for:

- SQL injection patterns
- Cross-site scripting (XSS)
- Path traversal (`../`, `%2e%2e%2f`)
- Known scanner User-Agents (sqlmap, nikto, nmap, masscan, etc.)
- Reverse shell / shellcode markers
- OS command injection

### Stateful Detectors

These are hardcoded behavioral detectors that don't fit the regex model:

| Rule ID | Trigger | Default Threshold |
| :--- | :--- | :--- |
| `PORT_SCAN` | N distinct destination ports from one source | 20 ports / 10s |
| `SYN_FLOOD` | N SYN packets from one source | 100 SYNs / 5s |
| `ICMP_FLOOD` | N ICMP packets from one source | 50 packets / 5s |
| `SSH_BRUTE` | N connection attempts to port 22 | 5 attempts / 60s |
| `DNS_FLOOD` | N DNS queries from one source | 100 queries / 30s |
| `DNS_BLACKLIST` | DNS query for a blacklisted domain | — |
| `BLACKLIST` | Any packet from a blacklisted IP | — |

Thresholds are tunable in the `Config` dataclass at the top of `pynids.py`.

---

## 🛡️ Automated Response

When a rule has `"action": "block"`, PyNIDS inserts matching `iptables` rules:

```bash
iptables -I INPUT   -s 203.0.113.66 -j DROP
iptables -I FORWARD -s 203.0.113.66 -j DROP
```

Each block has a TTL (default **1 hour**). A background janitor thread lifts expired blocks automatically.

### Safety rails

PyNIDS **refuses to block**:

- IPs in the `WHITELIST` config
- IPs in any `HOME_NET` subnet (unless `BLOCK_HOME_NET = True`)
- IPs in `/var/log/pynids/whitelist.txt` (if you create it)

### State persistence

Active blocks are written to `/var/log/pynids/state.json`. If PyNIDS crashes or restarts, the janitor thread picks up where it left off — no orphaned firewall rules, no duplicate inserts.

### Clean shutdown

By default, PyNIDS **leaves blocks in place** on `Ctrl+C` — your firewall stays protected while the IDS is down. Pass `--flush-on-exit` if you want the old "clean up everything" behaviour:

```bash
# Leave blocks — firewall stays hardened (default)
sudo python3 pynids.py sniff -i eth0

# Remove blocks on exit — restore pre-PyNIDS state
sudo python3 pynids.py sniff -i eth0 --flush-on-exit
```

---

## 🏗️ Architecture

```
                    ┌─────────────────────────────────────────┐
                    │  Network Interface (eth0)               │
                    └───────────────────┬─────────────────────┘
                                        │
                                        ▼
                    ┌─────────────────────────────────────────┐
                    │  Scapy sniffer (BPF filtered)           │
                    │  sniff(iface, prn=detector.process)     │
                    └───────────────────┬─────────────────────┘
                                        │
                                        ▼
              ┌──────────────────────────────────────────────────┐
              │  Detector.process(pkt)                           │
              │  ┌────────────────┐  ┌────────────────────────┐  │
              │  │ Blacklist IP?  │  │ Dispatch by protocol   │  │
              │  └───────┬────────┘  └───────┬────────────────┘  │
              │          │                   │                   │
              │          ▼                   ▼                   │
              │  ┌────────────────┐  ┌────────────────────────┐  │
              │  │ Signature      │  │ Stateful detectors     │  │
              │  │ Rules (regex)  │  │ (sliding windows)      │  │
              │  └───────┬────────┘  └───────┬────────────────┘  │
              │          │                   │                   │
              │          └──────────┬────────┘                   │
              │                     ▼                            │
              │          ┌────────────────────┐                  │
              │          │  Emit Alert        │                  │
              │          └──────────┬─────────┘                  │
              └─────────────────────┼────────────────────────────┘
                                    │
                    ┌───────────────┼────────────────┐
                    ▼               ▼                ▼
            ┌──────────────┐ ┌──────────────┐ ┌────────────────┐
            │ Alert log    │ │ Responder    │ │ Logging        │
            │ (rotating)   │ │ (iptables)   │ │ (console)      │
            └──────────────┘ └──────┬───────┘ └────────────────┘
                                    │
                                    ▼
                            ┌──────────────┐
                            │ state.json   │
                            │ (persistent) │
                            └──────────────┘

                    ┌──────────────────────────────┐
                    │  Flask Dashboard             │
                    │  reads alerts.json →         │
                    │  charts + table + auto-      │
                    │  refresh every 10s           │
                    └──────────────────────────────┘
```

### Code layout

| Section | Responsibility |
| :--- | :--- |
| `Config` | Frozen dataclass with all tunables and paths |
| `RotatingJSONLWriter` | Size-bounded, thread-safe JSONL writer |
| `SignatureRule` / `RuleSet` | Regex signature engine |
| `SlidingWindow` | Bounded-memory rate/distinct counters |
| `Responder` | `iptables` blocking with TTL and whitelist |
| `Detector` | Core engine — packet processing and alert emission |
| `cmd_sniff` | CLI wiring for live capture / pcap replay |
| `cmd_dashboard` | Flask app serving the Chart.js UI |
| `cmd_parse_eve` | Suricata EVE log ingestion |

---

## ⚙️ Configuration

Everything lives in the `Config` dataclass at the top of `pynids.py`:

```python
@dataclass(frozen=True)
class Config:
    # Network
    INTERFACE: str = "eth0"
    HOME_NET: Tuple[str, ...] = ("192.168.0.0/16", "10.0.0.0/8", ...)
    WHITELIST: FrozenSet[str] = frozenset({"1.1.1.1", "8.8.8.8"})

    # Detection thresholds
    PORT_SCAN_DISTINCT: int = 20
    SYN_FLOOD_COUNT: int = 100
    SSH_BRUTE_COUNT: int = 5
    # ... etc

    # Response
    AUTO_BLOCK: bool = True
    BLOCK_TTL: int = 3600
    BLOCK_HOME_NET: bool = False

    # Logging
    LOG_MAX_BYTES: int = 50 * 1024 * 1024
    LOG_BACKUPS: int = 5
```

### Environment overrides

| Variable | Effect |
| :--- | :--- |
| `PYNIDS_HOME` | Override the base log directory (default: `/var/log/pynids`) |

```bash
PYNIDS_HOME=/tmp/pynids python3 pynids.py dashboard
```

---

## 🧪 Testing Detections

From another machine, hit your PyNIDS host with the following:

| Attack | Command | Expected alert |
| :--- | :--- | :--- |
| TCP port scan | `nmap -sS -p 1-1000 <target>` | `PORT_SCAN` |
| SYN flood | `hping3 -S --flood -p 80 <target>` | `SYN_FLOOD` |
| ICMP flood | `sudo ping -f <target>` | `ICMP_FLOOD` |
| SSH brute force | `hydra -l root -P wordlist.txt ssh://<target>` | `SSH_BRUTE` |
| SQL injection | `curl "http://<target>/?id=1' UNION SELECT * FROM users--"` | `SQLI-001` |
| Scanner UA | `curl -A "sqlmap/1.7" http://<target>/` | `SCAN-TOOL-001` |
| Path traversal | `curl "http://<target>/../../etc/passwd"` | `TRAVERSAL-001` |
| Command injection | `curl "http://<target>/?cmd=;cat /etc/passwd"` | `CMD-INJ-001` |

> Run these against **your own** infrastructure only. PyNIDS is a defensive tool; testing it against systems you don't own is illegal.

---

## 🗺️ Roadmap

- [ ] **IPv6 support** — currently IPv4 only
- [ ] **TCP stream reassembly** — detect signatures split across segments
- [ ] **PCAP export** — dump offending flows for forensics
- [ ] **GeoIP enrichment** — map attack origins in the dashboard
- [ ] **Slack / Discord / webhook alerts** — push high-severity events
- [ ] **Rule hot-reload** — SIGHUP to re-read `rules.json`
- [ ] **PCRE2 backend** — swap in a faster regex engine
- [ ] **Prometheus metrics endpoint** — `/metrics` for scraping
- [ ] **Plugin API** — custom Python detectors as separate modules

Have a feature you want? [Open an issue](https://github.com/yourusername/pynids/issues).

---

## ⚠️ Limitations

PyNIDS is honest about what it isn't:

- **Throughput ceiling ~100 Mbps.** Scapy is single-threaded and Python-bound. For 1+ Gbps, use Suricata and forward alerts via `parse-eve`.
- **No TCP stream reassembly.** Signatures match against single-packet payloads. Split-across-segments attacks are missed.
- **No protocol parsers.** HTTP, TLS, SMB, etc. are treated as raw bytes. This limits detection quality on encrypted or complex protocols.
- **IPv4 only.** IPv6 traffic is dropped before analysis.
- **No dashboard auth.** Do not expose to the internet.
- **`iptables` only.** `nftables` and `pf` (macOS) are not supported for response.
- **Not a replacement for Suricata.** Run both. PyNIDS handles custom logic; Suricata handles the data path.

---

## ❓ FAQ

<details>
<summary><b>Why not just use Suricata?</b></summary>

Use Suricata if you need line-rate performance or its huge rule ecosystem. Use PyNIDS if you want to understand, customize, or prototype — or run both side by side and merge alerts with `parse-eve`.
</details>

<details>
<summary><b>Will this drop packets under load?</b></summary>

Yes, above roughly 100 Mbps. The stats loop reports `packets=` every 30 seconds — if this stops climbing while traffic is flowing, you're dropping. Consider increasing the BPF filter to reduce scope.
</details>

<details>
<summary><b>Can I run this on Windows?</b></summary>

Not natively. Use WSL2 for capture, but note that `iptables` response won't work — run with `--no-block`.
</details>

<details>
<summary><b>Can I run this without root?</b></summary>

Grant capabilities instead: `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))`. Or use `--no-block` and manually manage privileges.
</details>

<details>
<summary><b>How do I add a custom detection rule?</b></summary>

Edit `/var/log/pynids/rules.json` and restart the sniffer. Rules are validated at load time — malformed ones are logged and skipped without crashing the process.
</details>

<details>
<summary><b>Why is my dashboard empty?</b></summary>

Confirm `alerts.json` exists in `/var/log/pynids/`. If you set `PYNIDS_HOME`, the dashboard needs the same environment variable.
</details>

<details>
<summary><b>Is this production-ready?</b></summary>

No. It's a lab tool and teaching aid. See [Limitations](#-limitations).
</details>

---

## 🤝 Contributing

Contributions are welcome! Here's how to help:

1. **Fork** the repo and create a feature branch (`git checkout -b feature/my-detector`)
2. **Test** your change against a live capture and a pcap
3. **Submit** a PR with a clear description and, ideally, a pcap that exercises it

### Areas where help is especially welcome

- TCP stream reassembly (the big one)
- IPv6 support
- Additional stateful detectors (DNS tunneling, HTTP brute force, TLS fingerprinting)
- Rule syntax extensions (content modifiers like `nocase`, `depth`, `offset`)
- Packaging as a PyPI module

### Code style

- Single file, but keep sections clearly delimited
- Type hints everywhere
- No new runtime dependencies without discussion

---

## 📄 License

MIT — see [LICENSE](LICENSE).

Use it, fork it, sell it, wrap it in a startup pitch deck. Just don't blame us when it blocks your CI runner.

---

## 🙏 Acknowledgments

- [Scapy](https://scapy.net/) — the packet manipulation library that makes this possible
- [Suricata](https://suricata.io/) and [Snort](https://www.snort.org/) — the reference implementations this project learns from
- [Chart.js](https://www.chartjs.org/) — the dashboard charts
- [Flask](https://flask.palletsprojects.com/) — the dashboard server

---

<div align="center">

**⭐ If PyNIDS helped you learn something, star the repo. It helps others find it.**

[Report Bug](https://github.com/yourusername/pynids/issues) · [Request Feature](https://github.com/yourusername/pynids/issues) · [Read the Code](pynids.py)

</div>
