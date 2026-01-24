"""Utility functions for the AI incident response agent."""
import json
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
RUNTIME_STATE_FILE = BASE_DIR / "runtime_state.json"


def supply_logs():
    """Simulate supplying logs to the agent."""
    logs = ["2026-01-05T10:00:10 FIREWALL src_ip=45.33.32.156 dest_port=21 protocol=TCP tcp_flags=SYN action=BLOCKED",
"2026-01-05T10:00:35 FIREWALL src_ip=45.33.32.156 dest_port=22 protocol=TCP tcp_flags=FIN action=BLOCKED",
"2026-01-05T10:01:00 FIREWALL src_ip=45.33.32.156 dest_port=23 protocol=TCP tcp_flags=SYN action=BLOCKED",
"2026-01-05T10:01:25 FIREWALL src_ip=45.33.32.156 dest_port=25 protocol=TCP tcp_flags=FIN action=BLOCKED",
"2026-01-05T10:01:50 FIREWALL src_ip=45.33.32.156 dest_port=80 protocol=TCP tcp_flags=SYN action=BLOCKED",
"2026-01-05T10:02:20 FIREWALL src_ip=45.33.32.156 dest_port=443 protocol=TCP tcp_flags=FIN action=BLOCKED",

"2026-01-05T10:00:10 FIREWALL src_ip=45.33.32.156 dest_port=21 protocol=TCP tcp_flags=SYN action=BLOCKED",
"2026-01-05T10:00:40 FIREWALL src_ip=45.33.32.156 dest_port=22 protocol=TCP tcp_flags=FIN action=BLOCKED",
"2026-01-05T10:01:10 FIREWALL src_ip=45.33.32.156 dest_port=23 protocol=TCP tcp_flags=SYN action=BLOCKED",
"2026-01-05T10:01:40 FIREWALL src_ip=45.33.32.156 dest_port=25 protocol=TCP tcp_flags=FIN action=BLOCKED",
"2026-01-05T10:02:10 FIREWALL src_ip=45.33.32.156 dest_port=80 protocol=TCP tcp_flags=SYN action=BLOCKED",
"2026-01-05T10:02:40 FIREWALL src_ip=45.33.32.156 dest_port=443 protocol=TCP tcp_flags=FIN action=BLOCKED",

"2026-01-05T09:58:12 FIREWALL src_ip=192.168.1.10 dest_port=443 protocol=TCP tcp_flags=SYN,ACK action=ALLOWED",
"2026-01-05T09:58:40 FIREWALL src_ip=192.168.1.11 dest_port=80 protocol=TCP tcp_flags=SYN,ACK action=ALLOWED",
"2026-01-05T09:59:05 FIREWALL src_ip=192.168.1.12 dest_port=22 protocol=TCP tcp_flags=SYN,ACK action=ALLOWED",

"2026-01-05T10:00:01 FIREWALL src_ip=172.16.0.8 dest_port=53 protocol=UDP action=ALLOWED",
"2026-01-05T10:00:20 FIREWALL src_ip=192.168.1.13 dest_port=443 protocol=TCP tcp_flags=SYN,ACK action=ALLOWED",

"2026-01-05T10:02:01 FIREWALL src_ip=45.33.32.156 dest_port=22 protocol=TCP tcp_flags=SYN action=BLOCKED",
"2026-01-05T10:02:45 FIREWALL src_ip=45.33.32.156 dest_port=80 protocol=TCP tcp_flags=SYN,ACK action=ALLOWED",
"2026-01-05T10:03:30 FIREWALL src_ip=45.33.32.156 dest_port=443 protocol=TCP tcp_flags=FIN action=BLOCKED",

"2026-01-05T10:03:55 FIREWALL src_ip=192.168.1.14 dest_port=443 protocol=TCP tcp_flags=SYN,ACK action=ALLOWED",

"2026-01-05T10:05:10 FIREWALL src_ip=45.33.32.156 dest_port=21 protocol=TCP tcp_flags=SYN action=BLOCKED",
"2026-01-05T10:05:55 FIREWALL src_ip=45.33.32.156 dest_port=25 protocol=TCP tcp_flags=SYN action=BLOCKED",
"2026-01-05T10:06:40 FIREWALL src_ip=45.33.32.156 dest_port=110 protocol=TCP tcp_flags=FIN action=BLOCKED",
"2026-01-05T10:07:20 FIREWALL src_ip=45.33.32.156 dest_port=143 protocol=TCP tcp_flags=FIN action=BLOCKED",

"2026-01-05T10:07:50 FIREWALL src_ip=192.168.1.15 dest_port=80 protocol=TCP tcp_flags=SYN,ACK action=ALLOWED",

"2026-01-05T10:09:10 FIREWALL src_ip=45.33.32.156 dest_port=3306 protocol=TCP tcp_flags=SYN action=BLOCKED",
"2026-01-05T10:10:50 FIREWALL src_ip=45.33.32.156 dest_port=8080 protocol=TCP tcp_flags=FIN action=BLOCKED",

"2026-01-05T10:11:20 FIREWALL src_ip=192.168.1.16 dest_port=443 protocol=TCP tcp_flags=SYN,ACK action=ALLOWED",
"2026-01-05T10:11:55 FIREWALL src_ip=192.168.1.17 dest_port=22 protocol=TCP tcp_flags=SYN,ACK action=ALLOWED"
        ]

    for i, log in enumerate(logs):
        yield {"index": i, "log": log}



def serialize_for_json(obj):
    """Serialize an object for JSON encoding."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, set):
        return list(obj)
    if isinstance(obj, dict):
        return {k: serialize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [serialize_for_json(i) for i in obj]
    return obj


