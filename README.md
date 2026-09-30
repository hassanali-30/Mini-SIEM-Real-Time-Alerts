# Mini SIEM with Real-Time Alerts

[![CI](https://github.com/hassanali-30/Mini-SIEM-Real-Time-Alerts/actions/workflows/ci.yml/badge.svg)](https://github.com/hassanali-30/Mini-SIEM-Real-Time-Alerts/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

A local, defensive Mini SIEM for normalizing authorized logs, correlating events across sliding time windows, storing alerts in SQLite, and printing real-time notifications.

> **Safety boundary:** This project monitors supplied log files only. It does not collect credentials, block hosts, kill processes, scan networks, or execute automated response actions.

## Features

- JSONL and CSV log ingestion
- Common event-field normalization
- SQLite event and alert storage
- Sliding-window correlation rules
- Brute-force authentication detection
- Port-scan correlation
- Successful login after repeated failures
- Malware indicator followed by network activity
- Alert fingerprints and cooldown deduplication
- Real-time JSONL follow mode
- Localhost-only dashboard API
- JSON, terminal, and stored alert workflows
- Sample events, tests, CI, security policy, and license

## Installation

Requires Python 3.10 or newer.

```
git clone https://github.com/hassanali-30/Mini-SIEM-Real-Time-Alerts.git
cd Mini-SIEM-Real-Time-Alerts
python -m venv .venv
```

Activate the environment:

**Windows PowerShell**

```
.venv\\Scripts\\Activate.ps1
```

**macOS/Linux**

```
source .venv/bin/activate
```

Install dependencies:

```
python -m pip install -r requirements.txt
```

## Analyze a log file

Process the included sample:

```
python mini_siem.py --input sample_events.jsonl
```

The tool creates a local `siem.db` SQLite database and prints new alerts.

## Real-time follow mode

Follow an authorized local JSONL log stream:

```
python mini_siem.py --follow security-events.jsonl
```

Each new JSON object should contain at least a timestamp and event type. Common fields include `src_ip`, `username`, `host`, `dst_port`, `status`, and `message`.

## Dashboard API

Start the localhost-only API:

```
python mini_siem.py --dashboard --db siem.db --port 8765
```

Available endpoints:

- `GET /health`
- `GET /alerts`
- `GET /alerts?severity=high&limit=20`

The `/alerts` endpoint accepts an optional `severity` filter (`low`, `medium`, `high`, or `critical`) and a bounded `limit` from 1 to 500. This supports quick triage without downloading the full alert history.

The API binds to `127.0.0.1`; it is not an internet-facing dashboard.

## Correlation rules

Rules are configured in [rules/correlation_rules.json](rules/correlation_rules.json):

- **AUTH-BRUTE-FORCE:** repeated failed logins from one source in a time window
- **NET-PORT-SCAN:** one source contacts many destination ports
- **AUTH-SUCCESS-AFTER-FAILURES:** a success follows recent failures for the same account
- **MALWARE-NETWORK-CHAIN:** malware telemetry is followed by network activity on the same host

Alerts include a rule ID, severity, title, evidence, and a fingerprint. Alerts are deduplicated during the cooldown period.

## Project layout

```
mini_siem.py                 # Event pipeline, correlator, storage, and API
rules/correlation_rules.json # Threshold configuration
sample_events.jsonl          # Safe synthetic events
tests/                       # Offline unit tests
SECURITY.md                  # Defensive-use policy
```

## Testing

```
python -m pytest -q
```

## Limitations

This is a learning and defensive monitoring project. Detection quality depends on log coverage, field normalization, threshold tuning, and asset context. Validate rules against representative labeled data before using them operationally. Keep logs and SQLite databases protected because they may contain sensitive security telemetry.

## License

See [LICENSE](LICENSE).
