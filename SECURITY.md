# Security Policy

This is local defensive monitoring software.

## Safety boundaries

The Mini SIEM:

- processes authorized local logs and JSONL streams
- stores normalized events and alerts in SQLite
- does not collect credentials or full secret values
- does not block hosts, kill processes, scan networks, or execute response actions
- binds the optional dashboard API to localhost only

Logs and alert reports may contain sensitive IP addresses, usernames, hostnames, and timestamps. Protect the SQLite database and reports.

## Reporting

Use a private security report when possible. Do not publish credentials, tokens, or raw sensitive logs.