#!/usr/bin/env python3
"""
================================================================================
  PyNIDS — A Single-File Python Network Intrusion Detection System
================================================================================

  v2 — incorporates review fixes:
    [FIX-1] Tight DNS exception handling (no bare `except Exception`)
    [FIX-2] Bounded SlidingWindow (max events + pruned distinct map)
    [FIX-3] Per-rule cooldown override (falls back to global default)
    [FIX-4] Opt-in iptables flush on shutdown (--flush-on-exit)
    [FIX-5] Log rotation for alerts.json / blocked.json
    [FIX-6] Config as a frozen dataclass with immutable collections

  Usage
  -----
      sudo python3 pynids.py sniff -i eth0
      sudo python3 pynids.py sniff -i eth0 --no-block
      sudo python3 pynids.py sniff -i eth0 --flush-on-exit
      sudo python3 pynids.py sniff -r capture.pcap
             python3 pynids.py dashboard
             python3 pynids.py parse-eve
             python3 pynids.py init

  Requirements
  ------------
      pip install scapy flask
================================================================================
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import signal
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from ipaddress import ip_address, ip_network
from typing import Deque, Dict, FrozenSet, List, Optional, Set, Tuple

# ==============================================================================
# SECTION 1 — CONFIGURATION
# ==============================================================================
# [FIX-6] Frozen dataclass with immutable containers.
#   - HOME_NET is a tuple
#   - WHITELIST is a frozenset
#   - `Config.WHITELIST.add(...)` now raises AttributeError instead of silently
#     mutating shared state across the process.

@dataclass(frozen=True)
class Config:
    # -------- Network --------
    INTERFACE: str = "eth0"
    HOME_NET: Tuple[str, ...] = (
        "192.168.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
    )
    WHITELIST: FrozenSet[str] = frozenset({"1.1.1.1", "8.8.8.8"})

    # -------- Paths --------
    BASE_DIR: str = os.environ.get("PYNIDS_HOME", "/var/log/pynids")

    # -------- Detection thresholds --------
    PORT_SCAN_WINDOW: int = 10
    PORT_SCAN_DISTINCT: int = 20
    SYN_FLOOD_WINDOW: int = 5
    SYN_FLOOD_COUNT: int = 100
    ICMP_FLOOD_WINDOW: int = 5
    ICMP_FLOOD_COUNT: int = 50
    SSH_BRUTE_WINDOW: int = 60
    SSH_BRUTE_COUNT: int = 5
    DNS_FLOOD_WINDOW: int = 30
    DNS_FLOOD_COUNT: int = 100

    # -------- Alert behaviour --------
    ALERT_COOLDOWN: int = 60
    # [FIX-2] Cap retained events per window. Prevents memory blow-up under
    # extremely high cardinality scans (e.g. 100k-port scan from one source).
    WINDOW_MAX_EVENTS: int = 4096

    # -------- Response --------
    AUTO_BLOCK: bool = True
    BLOCK_TTL: int = 3600
    BLOCK_HOME_NET: bool = False
    # [FIX-4] Default: leave iptables rules in place on Ctrl+C.
    #   Only flush when --flush-on-exit (or this flag) is set.
    FLUSH_ON_EXIT: bool = False

    # -------- Log rotation --------
    # [FIX-5] Size-based rotation for alerts.json / blocked.json
    LOG_MAX_BYTES: int = 50 * 1024 * 1024   # 50 MB
    LOG_BACKUPS: int = 5

    # -------- Severity --------
    SEV_HIGH: int = 1
    SEV_MEDIUM: int = 2
    SEV_LOW: int = 3

    # -------- Dashboard --------
    DASHBOARD_HOST: str = "127.0.0.1"
    DASHBOARD_PORT: int = 5000

    # -------- Derived paths (properties aren't allowed on frozen dataclass
    #           fields the same way, so build them at access time) --------
    @property
    def ALERT_LOG(self) -> str:
        return os.path.join(self.BASE_DIR, "alerts.json")

    @property
    def BLOCK_LOG(self) -> str:
        return os.path.join(self.BASE_DIR, "blocked.json")

    @property
    def STATE_FILE(self) -> str:
        return os.path.join(self.BASE_DIR, "state.json")

    @property
    def RULES_FILE(self) -> str:
        return os.path.join(self.BASE_DIR, "rules.json")

    @property
    def BLACKLIST_FILE(self) -> str:
        return os.path.join(self.BASE_DIR, "blacklist.txt")


# Single process-wide instance. Access as CONFIG.INTERFACE etc.
CONFIG = Config()


# ==============================================================================
# SECTION 2 — LOGGING
# ==============================================================================

def setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)-18s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)


log = logging.getLogger("pynids")


# ==============================================================================
# SECTION 3 — ROTATING JSONL WRITER
# ==============================================================================
# [FIX-5] Size-bounded, thread-safe, JSON-lines writer with N backups.

class RotatingJSONLWriter:
    """
    Append JSON lines to `path`. When the file exceeds `max_bytes`, rotate:
        path.1 → path.2 → ... → path.N (dropped)
        path   → path.1
    Rotation is serialized with a lock so concurrent writers are safe.
    """

    def __init__(self, path: str, max_bytes: int, backups: int):
        self.path = path
        self.max_bytes = max(0, int(max_bytes))
        self.backups = max(0, int(backups))
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def _rotate(self) -> None:
        """Caller must hold self._lock."""
        if self.backups <= 0:
            # No backups requested → just truncate.
            try:
                os.remove(self.path)
            except FileNotFoundError:
                pass
            return

        # Shift existing backups: path.N-1 → path.N, ..., path.1 → path.2
        for i in range(self.backups - 1, 0, -1):
            src = f"{self.path}.{i}"
            dst = f"{self.path}.{i + 1}"
            if os.path.exists(src):
                try:
                    os.replace(src, dst)
                except OSError as exc:
                    log.warning("Rotation step %s → %s failed: %s", src, dst, exc)

        # Move current → path.1
        if os.path.exists(self.path):
            try:
                os.replace(self.path, f"{self.path}.1")
            except OSError as exc:
                log.warning("Rotation of %s failed: %s", self.path, exc)

    def write(self, record: dict) -> None:
        line = json.dumps(record) + "\n"
        with self._lock:
            try:
                if (self.max_bytes > 0
                        and os.path.exists(self.path)
                        and os.path.getsize(self.path) >= self.max_bytes):
                    self._rotate()
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line)
            except OSError as exc:
                log.error("Write to %s failed: %s", self.path, exc)


# ==============================================================================
# SECTION 4 — DEFAULT FILE BOOTSTRAP
# ==============================================================================

DEFAULT_RULES = {
    "rules": [
        {
            "id": "SQLI-001",
            "msg": "SQL Injection pattern in payload",
            "protocol": "tcp",
            "dst_port": [80, 443, 8080, 8443],
            "regex": r"(?i)(union[\s/+]+select|or\s+1\s*=\s*1|'\s*or\s*'|sleep\s*\(|benchmark\s*\()",
            "severity": 1,
            "action": "block",
            "cooldown": 30,
        },
        {
            "id": "XSS-001",
            "msg": "Cross-site scripting attempt",
            "protocol": "tcp",
            "dst_port": [80, 443, 8080],
            "regex": r"(?i)(<script[^>]*>|javascript:\s*alert|onerror\s*=)",
            "severity": 2,
            "action": "alert",
            "cooldown": 120,
        },
        {
            "id": "SCAN-TOOL-001",
            "msg": "Known scanner User-Agent",
            "protocol": "tcp",
            "dst_port": [80, 443, 8080],
            "regex": r"(?i)(sqlmap|nikto|nmap\s+scripting|masscan|acunetix|nessus)",
            "severity": 1,
            "action": "block",
            "cooldown": 60,
        },
        {
            "id": "TRAVERSAL-001",
            "msg": "Path traversal attempt",
            "protocol": "tcp",
            "dst_port": [80, 443, 8080],
            "regex": r"(?i)(\.\./|\.\.\\|%2e%2e%2f)",
            "severity": 2,
            "action": "alert",
            # No cooldown override → falls back to CONFIG.ALERT_COOLDOWN
        },
        {
            "id": "SHELL-001",
            "msg": "Possible reverse shell / shellcode markers",
            "protocol": "tcp",
            "dst_port": None,
            "regex": r"(?i)(/bin/(ba)?sh\s+-i|nc\s+-e\s+/bin/sh|bash\s+-c\s+')",
            "severity": 1,
            "action": "block",
            "cooldown": 10,
        },
        {
            "id": "CMD-INJ-001",
            "msg": "OS command injection markers",
            "protocol": "tcp",
            "dst_port": [80, 443, 8080],
            "regex": r"(;|\||`|\$\()\s*(cat|ls|whoami|id|wget|curl|nc)\b",
            "severity": 1,
            "action": "alert",
            "cooldown": 60,
        },
    ]
}

DEFAULT_BLACKLIST = """# One IP or domain per line. Lines starting with # are ignored.
# 203.0.113.66
# evil.example.com
"""


def bootstrap_files(force: bool = False) -> None:
    os.makedirs(CONFIG.BASE_DIR, exist_ok=True)

    if force or not os.path.exists(CONFIG.RULES_FILE):
        with open(CONFIG.RULES_FILE, "w", encoding="utf-8") as fh:
            json.dump(DEFAULT_RULES, fh, indent=2)
        log.info("Wrote default rules → %s", CONFIG.RULES_FILE)

    if force or not os.path.exists(CONFIG.BLACKLIST_FILE):
        with open(CONFIG.BLACKLIST_FILE, "w", encoding="utf-8") as fh:
            fh.write(DEFAULT_BLACKLIST)
        log.info("Wrote default blacklist → %s", CONFIG.BLACKLIST_FILE)


# ==============================================================================
# SECTION 5 — RULE ENGINE
# ==============================================================================
# [FIX-3] Each rule may define its own `cooldown` (seconds).

class SignatureRule:
    __slots__ = ("id", "msg", "severity", "action", "protocol",
                 "dst_ports", "pattern", "cooldown")

    def __init__(self, spec: dict):
        self.id = spec["id"]
        self.msg = spec["msg"]
        self.severity = int(spec.get("severity", 2))
        self.action = spec.get("action", "alert")
        self.protocol = (spec.get("protocol") or "").lower() or None
        self.dst_ports: Optional[List[int]] = spec.get("dst_port")
        # [FIX-3] Optional per-rule cooldown (seconds). None → use global.
        raw_cd = spec.get("cooldown")
        self.cooldown: Optional[float] = float(raw_cd) if raw_cd is not None else None
        self.pattern = (
            re.compile(spec["regex"].encode("utf-8", "ignore"), re.IGNORECASE)
            if spec.get("regex") else None
        )

    def match(self, protocol: str, dport: Optional[int],
              payload: Optional[bytes]) -> bool:
        if self.protocol and self.protocol != protocol:
            return False
        if self.dst_ports is not None and (dport is None or dport not in self.dst_ports):
            return False
        if self.pattern is not None:
            if not payload or not self.pattern.search(payload):
                return False
        return True


class RuleSet:
    def __init__(self, path: str):
        self.rules: List[SignatureRule] = []
        self._load(path)

    def _load(self, path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            log.warning("Rules file not found: %s", path)
            return
        except json.JSONDecodeError as exc:
            log.error("Malformed rules file: %s", exc)
            return

        for spec in data.get("rules", []):
            try:
                self.rules.append(SignatureRule(spec))
            except (KeyError, re.error, ValueError) as exc:
                log.error("Skipping invalid rule %s: %s", spec.get("id", "?"), exc)
        log.info("Loaded %d signature rules", len(self.rules))

    def evaluate(self, protocol: str, dport: Optional[int],
                 payload: Optional[bytes]) -> List[SignatureRule]:
        return [r for r in self.rules if r.match(protocol, dport, payload)]


# ==============================================================================
# SECTION 6 — AUTOMATED RESPONSE (iptables)
# ==============================================================================

class Responder:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        # [FIX-6] Copy immutable frozenset into a mutable set for runtime use.
        self.whitelist: Set[str] = set(CONFIG.WHITELIST)
        self.home_nets = [ip_network(n) for n in CONFIG.HOME_NET]
        self.blocked: Dict[str, float] = {}
        self._lock = threading.Lock()

        # [FIX-5] Rotating writer for the block log.
        self._block_writer = RotatingJSONLWriter(
            CONFIG.BLOCK_LOG, CONFIG.LOG_MAX_BYTES, CONFIG.LOG_BACKUPS,
        )

        self._load_whitelist_file()
        self._load_state()

        if self.enabled:
            threading.Thread(target=self._expire_loop, daemon=True).start()

    # ------------------------------------------------------------------ #
    def _load_whitelist_file(self) -> None:
        # NOTE: separate concern from the blacklist. Reads an optional
        # whitelist.txt if you add one; keeps the blacklist as-is.
        wl_path = os.path.join(CONFIG.BASE_DIR, "whitelist.txt")
        if not os.path.exists(wl_path):
            return
        try:
            with open(wl_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.whitelist.add(line)
        except OSError as exc:
            log.warning("Could not read whitelist: %s", exc)

    def _load_state(self) -> None:
        if not os.path.exists(CONFIG.STATE_FILE):
            return
        try:
            with open(CONFIG.STATE_FILE, "r", encoding="utf-8") as fh:
                self.blocked = json.load(fh)
            log.info("Restored %d active blocks", len(self.blocked))
        except (OSError, json.JSONDecodeError):
            pass

    def _save_state(self) -> None:
        try:
            with open(CONFIG.STATE_FILE, "w", encoding="utf-8") as fh:
                json.dump(self.blocked, fh)
        except OSError as exc:
            log.error("Could not persist block state: %s", exc)

    # ------------------------------------------------------------------ #
    @staticmethod
    def _run(cmd: list) -> bool:
        try:
            subprocess.run(cmd, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            return True
        except subprocess.CalledProcessError as exc:
            log.error("Command %s failed: %s",
                      " ".join(cmd), exc.stderr.decode().strip())
            return False
        except FileNotFoundError:
            log.error("iptables binary not found — response disabled")
            return False

    def _is_whitelisted(self, ip: str) -> bool:
        if ip in self.whitelist:
            return True
        if not CONFIG.BLOCK_HOME_NET:
            try:
                addr = ip_address(ip)
                if any(addr in net for net in self.home_nets):
                    return True
            except ValueError:
                return True
        return False

    # ------------------------------------------------------------------ #
    def block(self, ip: str, reason: str = "") -> bool:
        if not self.enabled:
            log.info("[DRY-RUN] would block %s (%s)", ip, reason)
            return False
        if self._is_whitelisted(ip):
            return False

        with self._lock:
            if ip in self.blocked:
                return False

            ok = self._run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
            ok &= self._run(["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"])
            if not ok:
                return False

            expiry = time.time() + CONFIG.BLOCK_TTL
            self.blocked[ip] = expiry
            self._save_state()
            self._log_event(ip, reason, expiry)

        log.warning("BLOCKED %s for %ds — %s", ip, CONFIG.BLOCK_TTL, reason)
        return True

    def unblock(self, ip: str) -> bool:
        with self._lock:
            if ip not in self.blocked:
                return False
            self._run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
            self._run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
            del self.blocked[ip]
            self._save_state()
        log.info("UNBLOCKED %s (TTL expired)", ip)
        return True

    def list_blocked(self) -> Dict[str, float]:
        return dict(self.blocked)

    def flush_all(self) -> None:
        for ip in list(self.blocked.keys()):
            self.unblock(ip)

    # ------------------------------------------------------------------ #
    def _log_event(self, ip: str, reason: str, expiry: float) -> None:
        # [FIX-5] Use rotating writer instead of raw append.
        self._block_writer.write({
            "timestamp": time.time(),
            "ip": ip,
            "reason": reason,
            "expires": expiry,
        })

    def _expire_loop(self) -> None:
        while True:
            time.sleep(30)
            now = time.time()
            for ip in [i for i, exp in list(self.blocked.items()) if exp <= now]:
                self.unblock(ip)


# ==============================================================================
# SECTION 7 — SLIDING WINDOW + ALERT DATA MODEL
# ==============================================================================
# [FIX-2] Bounded-memory SlidingWindow.
#   - events deque has maxlen (drops oldest under overflow)
#   - distinct map tracks last_seen so we can prune O(1)
#   - effective horizon = max(window cutoff, oldest retained event)

class SlidingWindow:
    __slots__ = ("window", "max_events", "events", "_distinct")

    def __init__(self, window: float, max_events: int = CONFIG.WINDOW_MAX_EVENTS):
        self.window = window
        self.max_events = max(1, int(max_events))
        self.events: Deque[Tuple[float, Optional[int]]] = deque(maxlen=self.max_events)
        self._distinct: Dict[int, float] = {}   # value → last_seen timestamp

    def _trim(self, now: float) -> None:
        cutoff = now - self.window

        # Drop stale events from the front of the deque.
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()

        # If the deque is at capacity, its oldest entry defines the true
        # horizon — anything older than that has been silently dropped.
        if len(self.events) >= self.max_events and self.events:
            cutoff = max(cutoff, self.events[0][0])

        # Prune stale distinct values.
        stale = [v for v, ts in self._distinct.items() if ts < cutoff]
        for v in stale:
            del self._distinct[v]

    def add(self, now: float, value: Optional[int] = None) -> None:
        self.events.append((now, value))
        if value is not None:
            self._distinct[value] = now
        self._trim(now)

    def count(self, now: float) -> int:
        self._trim(now)
        return len(self.events)

    def distinct(self, now: float) -> int:
        self._trim(now)
        return len(self._distinct)

    def clear(self) -> None:
        self.events.clear()
        self._distinct.clear()


@dataclass
class Alert:
    timestamp: float
    rule_id: str
    msg: str
    severity: int
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    action: str
    blocked: bool = False
    source: str = "pynids"

    def to_json(self) -> str:
        return json.dumps(asdict(self))


# ==============================================================================
# SECTION 8 — DETECTOR (core engine)
# ==============================================================================

class Detector:
    def __init__(self, responder: Optional[Responder] = None):
        self.responder = responder or Responder(enabled=False)
        self.rules = RuleSet(CONFIG.RULES_FILE)

        self.home_nets = [ip_network(n) for n in CONFIG.HOME_NET]
        self.blacklist = self._load_blacklist()

        self._windows: Dict[Tuple[str, str], SlidingWindow] = {}
        self._last_alert: Dict[Tuple[str, str], float] = {}
        self._lock = threading.Lock()

        self.stats = {"packets": 0, "alerts": 0, "blocked": 0}
        os.makedirs(CONFIG.BASE_DIR, exist_ok=True)

        # [FIX-5] Rotating writer for the alert log.
        self._alert_writer = RotatingJSONLWriter(
            CONFIG.ALERT_LOG, CONFIG.LOG_MAX_BYTES, CONFIG.LOG_BACKUPS,
        )

    # ------------------------------------------------------------------ #
    @staticmethod
    def _load_blacklist() -> Set[str]:
        if not os.path.exists(CONFIG.BLACKLIST_FILE):
            return set()
        with open(CONFIG.BLACKLIST_FILE, "r", encoding="utf-8") as fh:
            return {line.strip() for line in fh
                    if line.strip() and not line.startswith("#")}

    def _is_home(self, ip: str) -> bool:
        try:
            addr = ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.home_nets)

    def _window(self, key: Tuple[str, str], window: float) -> SlidingWindow:
        if key not in self._windows:
            # [FIX-2] Bounded size passed at construction.
            self._windows[key] = SlidingWindow(window, CONFIG.WINDOW_MAX_EVENTS)
        return self._windows[key]

    # [FIX-3] Accept an optional per-call cooldown override.
    def _cooled_down(self, rule_id: str, src: str, now: float,
                     override: Optional[float] = None) -> bool:
        key = (rule_id, src)
        cooldown = override if override is not None else CONFIG.ALERT_COOLDOWN
        if now - self._last_alert.get(key, 0.0) < cooldown:
            return False
        self._last_alert[key] = now
        return True

    # ------------------------------------------------------------------ #
    def emit(self, alert: Alert) -> None:
        with self._lock:
            self.stats["alerts"] += 1

        if alert.action == "block" and alert.src_ip:
            if self.responder.block(alert.src_ip, f"{alert.rule_id}: {alert.msg}"):
                alert.blocked = True
                self.stats["blocked"] += 1

        # [FIX-5] Rotating writer.
        self._alert_writer.write(asdict(alert))

        log.warning("[SEV%d] %s | %s -> %s | %s%s",
                    alert.severity, alert.rule_id, alert.src_ip,
                    alert.dst_ip, alert.msg,
                    " [BLOCKED]" if alert.blocked else "")

    # ------------------------------------------------------------------ #
    def process(self, pkt) -> None:
        from scapy.layers.inet import IP, TCP, UDP, ICMP      # noqa: F401
        from scapy.layers.dns import DNS                      # noqa: F401
        from scapy.packet import Raw                          # noqa: F401

        if IP not in pkt:
            return

        self.stats["packets"] += 1
        ip = pkt[IP]
        now = time.time()
        src, dst = ip.src, ip.dst

        if src in self.blacklist and self._cooled_down("BLACKLIST", src, now):
            self.emit(Alert(now, "BLACKLIST",
                            f"Traffic from blacklisted IP {src}",
                            CONFIG.SEV_HIGH, src, dst, None, None,
                            "ip", "block"))

        payload = bytes(pkt[Raw].load) if Raw in pkt else None

        if TCP in pkt:
            self._handle_tcp(pkt, ip, now, payload)
        elif UDP in pkt:
            self._handle_udp(pkt, ip, now, payload)
        elif ICMP in pkt:
            self._handle_icmp(ip, now)

    # ------------------------------------------------------------------ #
    def _handle_tcp(self, pkt, ip, now: float, payload: Optional[bytes]) -> None:
        from scapy.layers.inet import TCP

        tcp = pkt[TCP]
        src, dst = ip.src, ip.dst
        sport, dport = int(tcp.sport), int(tcp.dport)
        flags = int(tcp.flags)
        ext_to_home = (not self._is_home(src)) and self._is_home(dst)

        if ext_to_home and (flags & 0x02) and not (flags & 0x10):
            win = self._window(("PORT_SCAN", src), CONFIG.PORT_SCAN_WINDOW)
            win.add(now, dport)
            if win.distinct(now) >= CONFIG.PORT_SCAN_DISTINCT:
                if self._cooled_down("PORT_SCAN", src, now):
                    self.emit(Alert(now, "PORT_SCAN",
                                    f"TCP port scan: {win.distinct(now)} ports "
                                    f"in {CONFIG.PORT_SCAN_WINDOW}s",
                                    CONFIG.SEV_MEDIUM, src, dst, sport, dport,
                                    "tcp", "block"))
                    win.clear()

            flood = self._window(("SYN_FLOOD", src), CONFIG.SYN_FLOOD_WINDOW)
            flood.add(now)
            if flood.count(now) >= CONFIG.SYN_FLOOD_COUNT:
                if self._cooled_down("SYN_FLOOD", src, now):
                    self.emit(Alert(now, "SYN_FLOOD",
                                    f"SYN flood: {flood.count(now)} SYNs",
                                    CONFIG.SEV_HIGH, src, dst, sport, dport,
                                    "tcp", "block"))
                    flood.clear()

        if ext_to_home and dport == 22 and (flags & 0x02):
            win = self._window(("SSH_BRUTE", src), CONFIG.SSH_BRUTE_WINDOW)
            win.add(now)
            if win.count(now) >= CONFIG.SSH_BRUTE_COUNT:
                if self._cooled_down("SSH_BRUTE", src, now):
                    self.emit(Alert(now, "SSH_BRUTE",
                                    f"SSH brute force: {win.count(now)} attempts "
                                    f"in {CONFIG.SSH_BRUTE_WINDOW}s",
                                    CONFIG.SEV_HIGH, src, dst, sport, dport,
                                    "tcp", "block"))
                    win.clear()

        self._check_signatures("tcp", src, dst, sport, dport, payload, now)

    # ------------------------------------------------------------------ #
    def _handle_udp(self, pkt, ip, now: float, payload: Optional[bytes]) -> None:
        from scapy.layers.inet import UDP
        from scapy.layers.dns import DNS

        udp = pkt[UDP]
        src, dst = ip.src, ip.dst
        sport, dport = int(udp.sport), int(udp.dport)
        ext_to_home = (not self._is_home(src)) and self._is_home(dst)

        if ext_to_home and dport == 53:
            win = self._window(("DNS_FLOOD", src), CONFIG.DNS_FLOOD_WINDOW)
            win.add(now)
            if win.count(now) >= CONFIG.DNS_FLOOD_COUNT:
                if self._cooled_down("DNS_FLOOD", src, now):
                    self.emit(Alert(now, "DNS_FLOOD",
                                    f"High DNS rate: {win.count(now)} queries",
                                    CONFIG.SEV_MEDIUM, src, dst, sport, dport,
                                    "udp", "alert"))
                    win.clear()

        # [FIX-1] No more bare `except Exception`. We only tolerate the
        # narrow set of errors that malformed DNS packets actually raise.
        if DNS in pkt and pkt[DNS].qd is not None:
            try:
                qname = pkt[DNS].qd.qname.decode("utf-8", "ignore").rstrip(".")
            except (AttributeError, ValueError, UnicodeDecodeError) as exc:
                # log.debug — malformed packets are common on the wire.
                log.debug("Malformed DNS question from %s: %s", src, exc)
            else:
                for bad in self.blacklist:
                    if bad and (qname == bad or qname.endswith("." + bad)):
                        if self._cooled_down("DNS_BLACKLIST", src, now):
                            self.emit(Alert(now, "DNS_BLACKLIST",
                                            f"DNS query for blocked domain: {qname}",
                                            CONFIG.SEV_HIGH, src, dst, sport,
                                            dport, "udp", "alert"))
                        break

        self._check_signatures("udp", src, dst, sport, dport, payload, now)

    # ------------------------------------------------------------------ #
    def _handle_icmp(self, ip, now: float) -> None:
        src, dst = ip.src, ip.dst
        win = self._window(("ICMP_FLOOD", src), CONFIG.ICMP_FLOOD_WINDOW)
        win.add(now)
        if win.count(now) >= CONFIG.ICMP_FLOOD_COUNT:
            if self._cooled_down("ICMP_FLOOD", src, now):
                self.emit(Alert(now, "ICMP_FLOOD",
                                f"ICMP flood: {win.count(now)} packets",
                                CONFIG.SEV_MEDIUM, src, dst, None, None,
                                "icmp", "alert"))
                win.clear()

    # ------------------------------------------------------------------ #
    def _check_signatures(self, protocol: str, src: str, dst: str,
                          sport: int, dport: int,
                          payload: Optional[bytes], now: float) -> None:
        for rule in self.rules.evaluate(protocol, dport, payload):
            # [FIX-3] Per-rule cooldown override honoured here.
            if not self._cooled_down(rule.id, src, now, override=rule.cooldown):
                continue
            self.emit(Alert(now, rule.id, rule.msg, rule.severity,
                            src, dst, sport, dport, protocol, rule.action))

    # ------------------------------------------------------------------ #
    def prune_state(self, max_age: float = 300.0) -> None:
        now = time.time()
        for key in list(self._windows.keys()):
            win = self._windows[key]
            if not win.events or (now - win.events[-1][0]) > max_age:
                del self._windows[key]


# ==============================================================================
# SECTION 9 — SNIFF COMMAND
# ==============================================================================

def cmd_sniff(args) -> int:
    from scapy.all import sniff, PcapReader

    responder = Responder(enabled=not args.no_block and CONFIG.AUTO_BLOCK)
    detector = Detector(responder=responder)

    stop = threading.Event()

    def stats_loop():
        while not stop.wait(30):
            s = detector.stats
            log.info("packets=%d alerts=%d blocked=%d active_blocks=%d",
                     s["packets"], s["alerts"], s["blocked"],
                     len(responder.list_blocked()))
            detector.prune_state()

    threading.Thread(target=stats_loop, daemon=True).start()

    # [FIX-4] Shutdown only flushes iptables when explicitly requested.
    def shutdown(signum=None, frame=None):
        log.info("Shutting down ...")
        stop.set()

        if args.flush_on_exit:
            log.info("--flush-on-exit set: removing %d iptables rules",
                     len(responder.list_blocked()))
            responder.flush_all()
        else:
            log.info("Leaving %d iptables rules in place "
                     "(pass --flush-on-exit to remove them)",
                     len(responder.list_blocked()))

        s = detector.stats
        log.info("Final: packets=%d alerts=%d blocked=%d",
                 s["packets"], s["alerts"], s["blocked"])
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    log.info("PyNIDS starting")
    log.info("  interface  : %s", args.pcap or args.interface)
    log.info("  auto-block : %s", responder.enabled)
    log.info("  flush exit : %s", args.flush_on_exit)
    log.info("  home nets  : %s", ", ".join(CONFIG.HOME_NET))
    log.info("  rules      : %d", len(detector.rules.rules))

    try:
        if args.pcap:
            log.info("Replaying pcap: %s", args.pcap)
            with PcapReader(args.pcap) as reader:
                for pkt in reader:
                    detector.process(pkt)
        else:
            sniff(iface=args.interface, prn=detector.process,
                  store=False, filter=args.filter)
    except PermissionError:
        log.error("Permission denied — run with sudo")
        return 1
    except KeyboardInterrupt:
        shutdown()
    return 0


# ==============================================================================
# SECTION 10 — EVE PARSER (merge Suricata alerts)
# ==============================================================================

def cmd_parse_eve(args) -> int:
    def convert(event: dict) -> Optional[dict]:
        if event.get("event_type") != "alert":
            return None
        alert = event.get("alert", {})
        try:
            ts = datetime.fromisoformat(
                event.get("timestamp", "").replace("Z", "+00:00")
            ).timestamp()
        except (ValueError, AttributeError):
            ts = time.time()
        return {
            "timestamp": ts,
            "rule_id": f"SRC-{alert.get('signature_id', '0')}",
            "msg": alert.get("signature", "Suricata alert"),
            "severity": int(alert.get("severity", 2)),
            "src_ip": event.get("src_ip", ""),
            "dst_ip": event.get("dest_ip", ""),
            "src_port": event.get("src_port"),
            "dst_port": event.get("dest_port"),
            "protocol": event.get("proto", "").lower(),
            "action": "alert",
            "blocked": False,
            "source": "suricata",
        }

    path, out = args.file, args.out
    # [FIX-5] Rotating writer here too.
    writer = RotatingJSONLWriter(out, CONFIG.LOG_MAX_BYTES, CONFIG.LOG_BACKUPS)
    log.info("Watching %s → %s", path, out)

    while not os.path.exists(path):
        log.warning("Waiting for %s ...", path)
        time.sleep(2)

    fh = open(path, "r", encoding="utf-8")
    fh.seek(0, os.SEEK_END)

    try:
        while True:
            line = fh.readline()
            if not line:
                if (os.path.exists(path)
                        and os.stat(path).st_ino != os.fstat(fh.fileno()).st_ino):
                    log.info("Log rotated — reopening")
                    fh.close()
                    fh = open(path, "r", encoding="utf-8")
                time.sleep(0.5)
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            unified = convert(event)
            if unified:
                writer.write(unified)
    except KeyboardInterrupt:
        log.info("Stopped eve parser")
    finally:
        fh.close()
    return 0


# ==============================================================================
# SECTION 11 — DASHBOARD
# ==============================================================================

PAGE_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PyNIDS — Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root{--bg:#0f1419;--panel:#1a2029;--fg:#e6edf3;--muted:#8b949e;
        --high:#f85149;--med:#d29922;--low:#3fb950;--accent:#58a6ff;}
  *{box-sizing:border-box;}
  body{margin:0;font-family:-apple-system,Segoe UI,Roboto,sans-serif;
       background:var(--bg);color:var(--fg);}
  header{padding:20px 28px;border-bottom:1px solid #21262d;}
  h1{margin:0;font-size:20px;font-weight:600;}
  .sub{color:var(--muted);font-size:13px;margin-top:4px;}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
         gap:16px;padding:20px 28px;}
  .card{background:var(--panel);border:1px solid #21262d;border-radius:10px;
        padding:16px 18px;}
  .card .label{color:var(--muted);font-size:12px;text-transform:uppercase;
               letter-spacing:.06em;}
  .card .value{font-size:30px;font-weight:700;margin-top:6px;}
  .v-high{color:var(--high);}.v-med{color:var(--med);}
  .v-low{color:var(--low);}.v-acc{color:var(--accent);}
  .grid{display:grid;grid-template-columns:2fr 1fr;gap:16px;
        padding:0 28px 28px;}
  .panel{background:var(--panel);border:1px solid #21262d;border-radius:10px;
         padding:18px;}
  .panel h2{margin:0 0 14px;font-size:14px;font-weight:600;color:var(--muted);
            text-transform:uppercase;letter-spacing:.06em;}
  table{width:100%;border-collapse:collapse;font-size:13px;}
  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #21262d;}
  th{color:var(--muted);font-weight:500;font-size:11px;
     text-transform:uppercase;letter-spacing:.05em;}
  tr:hover td{background:#161b22;}
  .pill{display:inline-block;padding:2px 8px;border-radius:10px;
        font-size:11px;font-weight:600;}
  .p1{background:rgba(248,81,73,.15);color:var(--high);}
  .p2{background:rgba(210,153,34,.15);color:var(--med);}
  .p3{background:rgba(63,185,80,.15);color:var(--low);}
  .blk{color:var(--high);font-weight:600;}
  .scroll{max-height:420px;overflow-y:auto;}
  .full{grid-column:1 / -1;}
</style>
</head>
<body>
<header>
  <h1>🛡️ PyNIDS — Threat Dashboard</h1>
  <div class="sub">Auto-refresh 10s · {{ stats.total }} alerts</div>
</header>

<div class="cards">
  <div class="card"><div class="label">Total Alerts</div>
    <div class="value v-acc">{{ stats.total }}</div></div>
  <div class="card"><div class="label">High Severity</div>
    <div class="value v-high">{{ stats.severity.high }}</div></div>
  <div class="card"><div class="label">Medium Severity</div>
    <div class="value v-med">{{ stats.severity.medium }}</div></div>
  <div class="card"><div class="label">Low Severity</div>
    <div class="value v-low">{{ stats.severity.low }}</div></div>
  <div class="card"><div class="label">IPs Blocked</div>
    <div class="value v-high">{{ stats.blocked }}</div></div>
</div>

<div class="grid">
  <div class="panel full">
    <h2>Alert Timeline (per minute)</h2>
    <canvas id="timeline" height="70"></canvas>
  </div>
  <div class="panel"><h2>Top Signatures</h2>
    <canvas id="sigs" height="200"></canvas></div>
  <div class="panel"><h2>Top Sources</h2>
    <canvas id="srcs" height="200"></canvas></div>

  <div class="panel full">
    <h2>Recent Alerts</h2>
    <div class="scroll">
      <table>
        <thead><tr>
          <th>Time</th><th>Sev</th><th>Rule</th><th>Source</th>
          <th>Destination</th><th>Message</th><th>Blocked</th>
        </tr></thead>
        <tbody>
        {% for a in recent %}
          <tr>
            <td>{{ a.timestamp | int }}</td>
            <td><span class="pill p{{ a.severity }}">SEV{{ a.severity }}</span></td>
            <td>{{ a.rule_id }}</td>
            <td>{{ a.src_ip }}{% if a.src_port %}:{{ a.src_port }}{% endif %}</td>
            <td>{{ a.dst_ip }}{% if a.dst_port %}:{{ a.dst_port }}{% endif %}</td>
            <td>{{ a.msg }}</td>
            <td>{% if a.blocked %}<span class="blk">■</span>{% endif %}</td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</div>

<script>
const S = {{ stats | tojson }};
new Chart(document.getElementById('timeline'), {
  type:'line',
  data:{ labels:S.timeline.map(x=>x[0]),
         datasets:[{ label:'Alerts', data:S.timeline.map(x=>x[1]),
                     borderColor:'#58a6ff',
                     backgroundColor:'rgba(88,166,255,.15)',
                     fill:true, tension:.35, pointRadius:0, borderWidth:2 }] },
  options:{ plugins:{legend:{display:false}},
    scales:{ x:{ticks:{color:'#8b949e'},grid:{color:'#21262d'}},
             y:{ticks:{color:'#8b949e'},grid:{color:'#21262d'},
                beginAtZero:true} } }
});
new Chart(document.getElementById('sigs'), {
  type:'bar',
  data:{ labels:S.top_signatures.map(x=>x[0].slice(0,34)),
         datasets:[{ data:S.top_signatures.map(x=>x[1]),
                     backgroundColor:'#f85149', borderRadius:4 }] },
  options:{ indexAxis:'y', plugins:{legend:{display:false}},
    scales:{ x:{ticks:{color:'#8b949e'},grid:{color:'#21262d'},
                beginAtZero:true},
             y:{ticks:{color:'#8b949e',font:{size:10}},
                grid:{display:false}} } }
});
new Chart(document.getElementById('srcs'), {
  type:'bar',
  data:{ labels:S.top_sources.map(x=>x[0]),
         datasets:[{ data:S.top_sources.map(x=>x[1]),
                     backgroundColor:'#d29922', borderRadius:4 }] },
  options:{ indexAxis:'y', plugins:{legend:{display:false}},
    scales:{ x:{ticks:{color:'#8b949e'},grid:{color:'#21262d'},
                beginAtZero:true},
             y:{ticks:{color:'#8b949e'},grid:{display:false}} } }
});
setTimeout(()=>location.reload(), 10000);
</script>
</body>
</html>
"""


def _load_alerts(limit: int = 5000) -> List[dict]:
    alerts: List[dict] = []
    if not os.path.exists(CONFIG.ALERT_LOG):
        return alerts
    with open(CONFIG.ALERT_LOG, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return alerts[-limit:]


def _summarise(alerts: List[dict]) -> dict:
    sev = Counter()
    sig = Counter()
    src = Counter()
    timeline = defaultdict(int)

    for a in alerts:
        sev[a.get("severity", 3)] += 1
        sig[a.get("msg", "unknown")] += 1
        src[a.get("src_ip", "?")] += 1
        ts = a.get("timestamp", 0)
        timeline[datetime.fromtimestamp(ts).strftime("%H:%M")] += 1

    return {
        "total": len(alerts),
        "severity": {"high": sev.get(1, 0),
                     "medium": sev.get(2, 0),
                     "low": sev.get(3, 0)},
        "top_signatures": sig.most_common(10),
        "top_sources": src.most_common(10),
        "timeline": sorted(timeline.items()),
        "blocked": sum(1 for a in alerts if a.get("blocked")),
    }


def cmd_dashboard(args) -> int:
    from flask import Flask, jsonify, render_template_string

    app = Flask("pynids")

    @app.route("/")
    def index():
        return render_template_string(
            PAGE_TEMPLATE,
            stats=_summarise(_load_alerts()),
            recent=_load_alerts()[-50:][::-1],
        )

    @app.route("/api/stats")
    def api_stats():
        return jsonify(_summarise(_load_alerts()))

    @app.route("/api/alerts")
    def api_alerts():
        return jsonify(_load_alerts()[-200:][::-1])

    log.info("Dashboard: http://%s:%d", args.host, args.port)
    app.run(host=args.host, port=args.port, debug=False)
    return 0


# ==============================================================================
# SECTION 12 — CLI ENTRY POINT
# ==============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pynids",
        description="PyNIDS — single-file Python Network IDS",
    )
    p.add_argument("-v", "--verbose", action="store_true")

    sub = p.add_subparsers(dest="command", required=True)

    # ---- sniff ----
    s = sub.add_parser("sniff", help="Capture and analyze live traffic / pcap")
    s.add_argument("-i", "--interface", default=CONFIG.INTERFACE)
    s.add_argument("-r", "--pcap", help="Replay packets from a pcap file")
    s.add_argument("-f", "--filter", default="ip",
                   help="BPF capture filter (default: 'ip')")
    s.add_argument("--no-block", action="store_true",
                   help="Detect and alert only — do not modify iptables")
    # [FIX-4] Opt-in flush.
    s.add_argument("--flush-on-exit", action="store_true",
                   default=CONFIG.FLUSH_ON_EXIT,
                   help="Remove every iptables rule on Ctrl+C "
                        "(default: leave them installed)")
    s.set_defaults(func=cmd_sniff)

    # ---- dashboard ----
    d = sub.add_parser("dashboard", help="Start the web dashboard")
    d.add_argument("--host", default=CONFIG.DASHBOARD_HOST)
    d.add_argument("--port", type=int, default=CONFIG.DASHBOARD_PORT)
    d.set_defaults(func=cmd_dashboard)

    # ---- parse-eve ----
    e = sub.add_parser("parse-eve",
                       help="Merge Suricata eve.json into unified alert log")
    e.add_argument("-f", "--file", default="/var/log/suricata/eve.json")
    e.add_argument("-o", "--out", default=CONFIG.ALERT_LOG)
    e.set_defaults(func=cmd_parse_eve)

    # ---- init ----
    i = sub.add_parser("init", help="Create default rules/blacklist files")
    i.add_argument("--force", action="store_true",
                   help="Overwrite existing files")
    i.set_defaults(func=lambda a: (bootstrap_files(a.force), 0)[1])

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    setup_logging(args.verbose)

    if args.command != "init":
        bootstrap_files(force=False)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())