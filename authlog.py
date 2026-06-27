"""
authlog.py - Recover a per-connection clientID with **stock** sshd, no patch.

Every SSH connection authenticates, and sshd logs the result with the client's
source ip:port and key identity, e.g.:

  sshd-session[8111]: Accepted publickey for tun from 10.50.50.158 port 42668 \
      ssh2: ED25519 SHA256:AbCd...
  sshd-session[8111]: Accepted publickey for tun from 10.50.50.158 port 42668 \
      ssh2: ED25519-CERT SHA256:AbCd... ID edge-77 (serial 5) CA ED25519 SHA256:..

We join those lines to live connections on (client_ip, source_port) -- the
scanner already has that 4-tuple from the socket, and it is unique per TCP
connection, so it works for -N forwarding-only sessions and survives PID reuse.

clientID resolution, in order:
  1. certificate key ID ("ID <keyid>")              -> used directly
  2. raw-key fingerprint ("SHA256:...")             -> looked up in a JSON map
  3. login username                                 -> looked up in the map
A JSON map (SSHRF_CLIENTID_MAP) can override any of these; for raw keys and
usernames it is required, since a bare fingerprint is not a friendly name.
"""

import os
import re
import json
import time
import subprocess

ACCEPTED_RE = re.compile(
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+"
    r"(?P<ip>[0-9a-fA-F:.]+)\s+port\s+(?P<port>\d+)"
)
FP_RE = re.compile(r"ssh2:\s+(?P<keytype>\S+)\s+(?P<fp>SHA256:[A-Za-z0-9+/=]+)")
CERTID_RE = re.compile(r"\bID\s+(?P<keyid>\S+)\s+\(serial\b")

_CACHE = {"ts": 0.0, "table": None}
_CACHE_TTL = 5.0  # the UI polls every 8s; avoid re-reading the journal each time


def parse_accepted(lines):
    """lines (chronological) -> {(ip, port): {user, method, fingerprint, key_id}}.

    Later entries win, so a reused ip:port resolves to the most recent login
    (the one that is currently open)."""
    table = {}
    for line in lines:
        m = ACCEPTED_RE.search(line)
        if not m:
            continue
        rec = {
            "user": m.group("user"), "method": m.group("method"),
            "fingerprint": None, "key_id": None,
        }
        fm = FP_RE.search(line)
        if fm:
            rec["fingerprint"] = fm.group("fp")
            if fm.group("keytype").upper().endswith("-CERT"):
                cm = CERTID_RE.search(line)
                if cm:
                    rec["key_id"] = cm.group("keyid")
        table[(m.group("ip"), int(m.group("port")))] = rec
    return table


def _read_sources():
    """Pull sshd 'Accepted' lines for the current boot. journalctl first
    (filtered server-side with -g for cheapness), then flat log files."""
    cmd = ["journalctl", "-b", "--no-pager", "-o", "cat",
           "-t", "sshd", "-t", "sshd-session", "-g", "Accepted "]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if out.returncode == 0 and out.stdout:
            return out.stdout.splitlines()
    except (FileNotFoundError, subprocess.SubprocessError):
        pass
    lines = []
    for path in ("/var/log/auth.log", "/var/log/secure"):
        try:
            with open(path, errors="replace") as fh:
                lines.extend(fh.read().splitlines())
        except (FileNotFoundError, PermissionError):
            pass
    return lines


def auth_table(force=False):
    now = time.time()
    if not force and _CACHE["table"] is not None and now - _CACHE["ts"] < _CACHE_TTL:
        return _CACHE["table"]
    table = parse_accepted(_read_sources())
    _CACHE.update(ts=now, table=table)
    return table


def load_id_map(path=None):
    path = path or os.environ.get("SSHRF_CLIENTID_MAP")
    if not path:
        return {}
    try:
        with open(path) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def resolve(ip, port, table=None, id_map=None):
    """Best clientID for a connection, or None if it can't be resolved."""
    table = auth_table() if table is None else table
    id_map = load_id_map() if id_map is None else id_map
    rec = table.get((ip, port))
    if not rec:
        return None
    if rec["key_id"]:                       # certificate: key ID is the identity
        return id_map.get(rec["key_id"], rec["key_id"])
    if rec["fingerprint"] and rec["fingerprint"] in id_map:
        return id_map[rec["fingerprint"]]
    if rec["user"] and rec["user"] in id_map:
        return id_map[rec["user"]]
    return None
