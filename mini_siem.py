#!/usr/bin/env python3
"""Defensive mini-SIEM with local event correlation and real-time alerts.

The application processes authorized local log files or JSONL streams. It does
not collect credentials, block hosts, scan networks, or execute responses.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import http.server
import json
import sqlite3
import sys
import time
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Thread
from typing import Any, Iterable


@dataclass(frozen=True)
class Event:
    timestamp: float
    source: str
    event_type: str
    username: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    status: str | None = None
    host: str | None = None
    severity: str | None = None
    message: str = ""
    raw: dict[str, Any] | None = None


def parse_timestamp(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    try:
        return float(text)
    except ValueError:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()


def normalize_event(row: dict[str, Any]) -> Event:
    def pick(*names: str, default: Any = None) -> Any:
        lowered = {str(key).lower(): value for key, value in row.items()}
        for name in names:
            if name.lower() in lowered and lowered[name.lower()] not in ("", None):
                return lowered[name.lower()]
        return default

    raw_port = pick("dst_port", "destination_port", "dport")
    return Event(
        timestamp=parse_timestamp(pick("timestamp", "time", "@timestamp")),
        source=str(pick("source", "log_source", "source_type", default="unknown")),
        event_type=str(pick("event_type", "type", "event.action", "action", default="unknown")).lower(),
        username=pick("username", "user", "user.name"),
        src_ip=pick("src_ip", "source_ip", "src", "source.address"),
        dst_ip=pick("dst_ip", "destination_ip", "dst", "destination.address"),
        dst_port=int(float(raw_port)) if raw_port not in (None, "") else None,
        status=pick("status", "result", "outcome"),
        host=pick("host", "hostname", "host.name"),
        severity=pick("severity", "level"),
        message=str(pick("message", "msg", default="")),
        raw=row,
    )


def read_events(path: str | Path) -> Iterable[Event]:
    file_path = Path(path)
    if file_path.suffix.lower() in {".json", ".jsonl"}:
        with file_path.open(encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    payload = json.loads(line)
                    if isinstance(payload, dict):
                        yield normalize_event(payload)
    else:
        with file_path.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                yield normalize_event(row)


class AlertStore:
    def __init__(self, path: str = "siem.db") -> None:
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                source TEXT, event_type TEXT, username TEXT, src_ip TEXT,
                dst_ip TEXT, dst_port INTEGER, status TEXT, host TEXT,
                severity TEXT, message TEXT, raw_json TEXT
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT UNIQUE NOT NULL,
                created_at REAL NOT NULL,
                rule_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                acknowledged INTEGER NOT NULL DEFAULT 0
            );
        """)
        self.connection.commit()

    def save_event(self, event: Event) -> None:
        self.connection.execute(
            """INSERT INTO events(timestamp,source,event_type,username,src_ip,dst_ip,
               dst_port,status,host,severity,message,raw_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                event.timestamp, event.source, event.event_type, event.username,
                event.src_ip, event.dst_ip, event.dst_port, event.status, event.host,
                event.severity, event.message, json.dumps(event.raw or {}),
            ),
        )
        self.connection.commit()

    def save_alert(self, alert: dict[str, Any], cooldown: int = 300) -> bool:
        fingerprint = alert["fingerprint"]
        existing = self.connection.execute(
            "SELECT created_at FROM alerts WHERE fingerprint=?", (fingerprint,)
        ).fetchone()
        now = time.time()
        if existing and now - float(existing["created_at"]) < cooldown:
            return False
        if existing:
            self.connection.execute(
                "UPDATE alerts SET created_at=?, evidence_json=?, acknowledged=0 WHERE fingerprint=?",
                (now, json.dumps(alert["evidence"]), fingerprint),
            )
        else:
            self.connection.execute(
                """INSERT INTO alerts(fingerprint,created_at,rule_id,severity,title,evidence_json)
                   VALUES(?,?,?,?,?,?)""",
                (
                    fingerprint, now, alert["rule_id"], alert["severity"],
                    alert["title"], json.dumps(alert["evidence"]),
                ),
            )
        self.connection.commit()
        return True

    def recent_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]

    def close(self) -> None:
        self.connection.close()


class Correlator:
    def __init__(self, rules: dict[str, int] | None = None) -> None:
        configured = {
            "brute_force_threshold": 5,
            "brute_force_window": 300,
            "port_scan_threshold": 10,
            "port_scan_window": 120,
            "post_failure_window": 300,
            "malware_chain_window": 600,
        }
        configured.update(rules or {})
        self.rules = configured
        self.events: deque[Event] = deque(maxlen=5000)

    def _window(self, now: float, seconds: int) -> list[Event]:
        return [event for event in self.events if now - event.timestamp <= seconds]

    @staticmethod
    def _alert(rule_id: str, severity: str, title: str, evidence: dict[str, Any]) -> dict[str, Any]:
        identity = f"{rule_id}:{json.dumps(evidence, sort_keys=True)}"
        return {
            "fingerprint": hashlib.sha256(identity.encode()).hexdigest(),
            "rule_id": rule_id,
            "severity": severity,
            "title": title,
            "evidence": evidence,
        }

    def process(self, event: Event) -> list[dict[str, Any]]:
        self.events.append(event)
        alerts: list[dict[str, Any]] = []
        recent = self._window(event.timestamp, self.rules["brute_force_window"])

        if event.event_type in {"login_failed", "authentication_failure", "failed_login"} and event.src_ip:
            failures = [
                item for item in recent
                if item.src_ip == event.src_ip
                and item.event_type in {"login_failed", "authentication_failure", "failed_login"}
            ]
            if len(failures) >= self.rules["brute_force_threshold"]:
                alerts.append(self._alert(
                    "AUTH-BRUTE-FORCE", "high", "Repeated authentication failures",
                    {"src_ip": event.src_ip, "count": len(failures), "window_seconds": self.rules["brute_force_window"]},
                ))

        if event.src_ip and event.dst_port is not None:
            scan_window = self._window(event.timestamp, self.rules["port_scan_window"])
            ports = {item.dst_port for item in scan_window if item.src_ip == event.src_ip and item.dst_port is not None}
            if len(ports) >= self.rules["port_scan_threshold"]:
                alerts.append(self._alert(
                    "NET-PORT-SCAN", "medium", "Possible port scan",
                    {"src_ip": event.src_ip, "distinct_ports": sorted(ports), "window_seconds": self.rules["port_scan_window"]},
                ))

        if event.status and event.status.lower() in {"success", "succeeded", "allowed"} and event.username:
            failures = [
                item for item in recent
                if item.username == event.username
                and item.event_type in {"login_failed", "authentication_failure", "failed_login"}
            ]
            if failures:
                alerts.append(self._alert(
                    "AUTH-SUCCESS-AFTER-FAILURES", "high", "Successful login after failures",
                    {"username": event.username, "src_ip": event.src_ip, "failed_count": len(failures)},
                ))

        if event.event_type in {"malware_detected", "malware_alert", "keylogger_indicator"} and event.host:
            chain = [
                item for item in recent
                if item.host == event.host and item.event_type in {"network_connection", "dns_query", "outbound_connection"}
            ]
            if chain:
                alerts.append(self._alert(
                    "MALWARE-NETWORK-CHAIN", "critical", "Malware indicator followed by network activity",
                    {"host": event.host, "network_events": len(chain)},
                ))
        return alerts


def load_rules(path: str) -> dict[str, int]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return {str(key): int(value) for key, value in payload.items()}


def process_file(path: str, db_path: str, rules: dict[str, int]) -> list[dict[str, Any]]:
    store = AlertStore(db_path)
    correlator = Correlator(rules)
    emitted: list[dict[str, Any]] = []
    try:
        for event in read_events(path):
            store.save_event(event)
            for alert in correlator.process(event):
                if store.save_alert(alert):
                    emitted.append(alert)
                    print_alert(alert)
    finally:
        store.close()
    return emitted


def follow_file(path: str, db_path: str, rules: dict[str, int], poll_seconds: float = 0.5) -> None:
    store = AlertStore(db_path)
    correlator = Correlator(rules)
    try:
        with Path(path).open(encoding="utf-8") as handle:
            handle.seek(0, 2)
            while True:
                line = handle.readline()
                if not line:
                    time.sleep(poll_seconds)
                    continue
                if not line.strip():
                    continue
                payload = json.loads(line)
                event = normalize_event(payload)
                store.save_event(event)
                for alert in correlator.process(event):
                    if store.save_alert(alert):
                        print_alert(alert)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        store.close()


def print_alert(alert: dict[str, Any]) -> None:
    print(f"[ALERT][{alert['severity'].upper()}] {alert['rule_id']}: {alert['title']}")
    print(f"        Evidence: {json.dumps(alert['evidence'], sort_keys=True)}")


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    store: AlertStore | None = None

    def do_GET(self) -> None:
        if self.path == "/health":
            body = json.dumps({"status": "ok", "service": "mini-siem"}).encode()
        elif self.path == "/alerts":
            body = json.dumps(self.store.recent_alerts() if self.store else []).encode()
        else:
            body = b'{"service":"mini-siem","endpoints":["/health","/alerts"]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_: Any) -> None:
        return


def serve_dashboard(db_path: str, port: int) -> None:
    DashboardHandler.store = AlertStore(db_path)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), DashboardHandler)
    print(f"Dashboard API listening on http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
    finally:
        DashboardHandler.store.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Local defensive mini-SIEM")
    parser.add_argument("--input", help="CSV or JSONL log file")
    parser.add_argument("--follow", help="Follow a local JSONL file for real-time alerts")
    parser.add_argument("--rules", default="rules/correlation_rules.json")
    parser.add_argument("--db", default="siem.db")
    parser.add_argument("--dashboard", action="store_true", help="Serve localhost alert API")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not args.input and not args.follow and not args.dashboard:
        parser.error("Use --input, --follow, or --dashboard")
    try:
        rules = load_rules(args.rules)
        if args.input:
            process_file(args.input, args.db, rules)
        if args.follow:
            follow_file(args.follow, args.db, rules)
        if args.dashboard:
            serve_dashboard(args.db, args.port)
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
