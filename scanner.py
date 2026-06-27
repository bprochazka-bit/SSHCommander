"""
scanner.py - Correlate inbound SSH connections with the reverse-port-forward
listeners they created, by walking /proc and /proc/net/tcp{,6}.

The join key is the PID of the per-session sshd worker. That single process
holds *both* the ESTABLISHED socket to the client (local port == the sshd
listen port) and the LISTEN socket(s) it opened for each `ssh -R` forward.
No guessing required: same PID owns both fds.

Needs root to read other users' /proc/<pid>/fd. Works on classic OpenSSH
(comm 'sshd') and on OpenSSH >= 9.8 where sessions run as 'sshd-session'.
"""

import os
import re
import glob
import socket

import authlog

SESSION_COMMS = {"sshd", "sshd-session"}

# Environment variable the patched sshd/clients set per connection.
CLIENT_ID_VAR = "clientID"

# Same value as it may appear in the worker's process title (setproctitle),
# e.g. "sshd-session: user@notty (clientID=edge-77)". The proctitle is the
# reliable source for -N forwarding-only sessions (no shell child) and for any
# value learned mid-connection, since /proc/<pid>/cmdline updates at runtime
# whereas /proc/<pid>/environ is frozen at exec time. Accepts '=' or ':' and
# stops at whitespace or a closing bracket/paren.
CLIENT_ID_TITLE_RE = re.compile(
    re.escape(CLIENT_ID_VAR) + r"\s*[=:]\s*([^\s\]\)}>]+)"
)

TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT",  "03": "SYN_RECV",
    "04": "FIN_WAIT1",   "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE",       "08": "CLOSE_WAIT","09": "LAST_ACK",
    "0A": "LISTEN",      "0B": "CLOSING",
}


def _parse_v4(token):
    addr, port = token.split(":")
    ip = socket.inet_ntoa(bytes.fromhex(addr)[::-1])  # stored little-endian
    return ip, int(port, 16)


def _parse_v6(token):
    addr, port = token.split(":")
    raw = bytes.fromhex(addr)                          # 16 bytes
    words = [raw[i:i + 4][::-1] for i in range(0, 16, 4)]  # per-32bit-word swap
    ip = socket.inet_ntop(socket.AF_INET6, b"".join(words))
    return ip, int(port, 16)


def _read_net_tcp(path, parser, family):
    rows = {}
    try:
        with open(path) as fh:
            next(fh)  # skip header
            for line in fh:
                p = line.split()
                if len(p) < 10:
                    continue
                local_ip, local_port = parser(p[1])
                remote_ip, remote_port = parser(p[2])
                rows[int(p[9])] = {  # key is socket inode
                    "family": family,
                    "local_ip": local_ip, "local_port": local_port,
                    "remote_ip": remote_ip, "remote_port": remote_port,
                    "state": TCP_STATES.get(p[3].upper(), p[3]),
                }
    except FileNotFoundError:
        pass
    return rows


def socket_table():
    """inode -> socket info, across IPv4 and IPv6."""
    table = {}
    table.update(_read_net_tcp("/proc/net/tcp", _parse_v4, "ipv4"))
    table.update(_read_net_tcp("/proc/net/tcp6", _parse_v6, "ipv6"))
    return table


def _user_from_cmdline(cmdline):
    # "sshd: alice@pts/0" / "sshd: alice@notty" / "sshd-session: alice [priv]"
    body = cmdline.split(":", 1)[-1].strip()
    m = re.match(r"([^@\s]+)", body)
    return m.group(1) if m else "?"


def _classify_role(cmdline):
    """
    Privilege-separation role from the sshd process title. A single SSH session
    is several processes that all inherit the inbound network socket:
      monitor   "sshd-session: user [priv]"   (privileged, holds no forwards)
      worker    "sshd-session: user@notty"    (unprivileged, opens -R listeners)
      preauth   "...[net]" / "...[pre-auth]"  (transient, before auth completes)
      listener  "sshd: ... [listener]"        (the master accept loop)
    The worker is the real session endpoint we want to surface.
    """
    c = cmdline.lower()
    if "[priv]" in c:
        return "monitor"
    if "[listener]" in c:
        return "listener"
    if "[net]" in c or "[pre-auth]" in c or "[accepted]" in c:
        return "preauth"
    if "@" in cmdline:
        return "worker"
    return "other"


def _client_id_from_cmdline(cmdline):
    """Pull clientID from the process title if the patched sshd put it there."""
    m = CLIENT_ID_TITLE_RE.search(cmdline)
    return m.group(1) if m else None


def _ppid(pid):
    """Parent PID from /proc/<pid>/stat, robust to spaces/parens in comm."""
    try:
        with open(f"/proc/{pid}/stat") as fh:
            data = fh.read()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    rparen = data.rfind(")")  # comm is the only field that can hold ')'
    if rparen == -1:
        return None
    fields = data[rparen + 2:].split()  # [state, ppid, ...]
    try:
        return int(fields[1])
    except (IndexError, ValueError):
        return None


def _children_index():
    """ppid -> [child pids] across all processes (one cheap /proc pass)."""
    idx = {}
    for pid_dir in glob.glob("/proc/[0-9]*"):
        try:
            pid = int(os.path.basename(pid_dir))
        except ValueError:
            continue
        pp = _ppid(pid)
        if pp is not None:
            idx.setdefault(pp, []).append(pid)
    return idx


def _client_id_from_children(pid, child_idx):
    """clientID from a session command child's environ (stock AcceptEnv path).

    With `AcceptEnv clientID` on the server and a non-`-N` client that runs a
    keepalive command, sshd forks that command under the worker with clientID
    in its environment. Read it from the child rather than the worker, since the
    worker's own environ never holds it.
    """
    for child in child_idx.get(pid, []):
        cid = _read_client_id(f"/proc/{child}")
        if cid:
            return cid
    return None


def _read_client_id(pid_dir):
    """
    Pull just the clientID var from /proc/<pid>/environ, or None if absent
    (legacy clients) or unreadable. Only this one var is extracted; the rest of
    the environment may hold secrets and is never exposed.

    Caveat: /proc/<pid>/environ reflects the environment as it was at exec time,
    not later setenv()/putenv() calls. The sshd patch must place clientID in the
    session process's environment *before* it execs (so it lands in the initial
    block), otherwise it will not show up here.
    """
    try:
        with open(f"{pid_dir}/environ", "rb") as fh:
            raw = fh.read()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return None
    for entry in raw.split(b"\x00"):
        key, sep, val = entry.partition(b"=")
        if sep and key.decode("utf-8", "replace") == CLIENT_ID_VAR:
            return val.decode("utf-8", "replace")
    return None


def _sshd_procs():
    """pid -> {cmdline, comm, inodes:set}. Tracks fd-read permission failures."""
    procs = {}
    denied = False
    for pid_dir in glob.glob("/proc/[0-9]*"):
        try:
            with open(f"{pid_dir}/comm") as fh:
                comm = fh.read().strip()
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        if comm not in SESSION_COMMS:
            continue
        try:
            with open(f"{pid_dir}/cmdline", "rb") as fh:
                cmdline = fh.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        except Exception:
            cmdline = comm
        inodes = set()
        fd_dir = f"{pid_dir}/fd"
        try:
            for fd in os.listdir(fd_dir):
                try:
                    target = os.readlink(f"{fd_dir}/{fd}")
                except (FileNotFoundError, PermissionError):
                    continue
                if target.startswith("socket:["):
                    inodes.add(int(target[8:-1]))
        except PermissionError:
            denied = True
            continue
        except (FileNotFoundError, ProcessLookupError):
            continue
        procs[int(os.path.basename(pid_dir))] = {
            "comm": comm, "cmdline": cmdline, "inodes": inodes,
            # Proctitle is authoritative (works for -N, updates at runtime);
            # environ is a fallback for setups that export it at exec time.
            "client_id": _client_id_from_cmdline(cmdline) or _read_client_id(pid_dir),
        }
    return procs, denied


def scan(ssh_ports=None):
    """
    Returns:
      {
        "ssh_ports": [22, ...],
        "privileged": bool,
        "permission_warning": bool,
        "connections": [
          {pid, pids, comm, username, client_id, client_ip, client_port,
           server_port, forwards: [{bind_ip, port, family}, ...]},
          ...
        ]
      }

    One inbound SSH session spans several sshd processes (privsep monitor +
    worker, plus transient pre-auth). They all share the inbound socket inode,
    so sessions are deduped by that inode: `pid` is the chosen worker, `pids`
    lists every process in the session.
    """
    socks = socket_table()
    procs, denied = _sshd_procs()

    # Discover the master listener port(s): a LISTEN socket owned by an sshd
    # whose cmdline marks it as the listener ("[listener]" in modern OpenSSH).
    listener_ports = set()
    for info in procs.values():
        if "listener" in info["cmdline"].lower():
            for ino in info["inodes"]:
                s = socks.get(ino)
                if s and s["state"] == "LISTEN":
                    listener_ports.add(s["local_port"])
    if ssh_ports:
        listener_ports |= set(ssh_ports)
    if not listener_ports:
        listener_ports = {22}

    # Group every sshd process that holds the same inbound connection. The
    # monitor and the worker for one session both inherit that socket (same
    # open file description -> same inode), so the inode is an exact dedup key.
    # Forwards are opened post-fork by the worker only, so they land on whichever
    # process is the real worker; we union them across the group regardless.
    groups = {}  # inbound_inode -> aggregated session
    for pid, info in procs.items():
        inbound = inbound_ino = None
        forwards = {}  # listen inode -> socket info (dedupes shared fds)
        for ino in info["inodes"]:
            s = socks.get(ino)
            if not s:
                continue
            if s["state"] == "ESTABLISHED" and s["local_port"] in listener_ports:
                inbound, inbound_ino = s, ino  # client's connection to sshd
            elif s["state"] == "LISTEN" and s["local_port"] not in listener_ports:
                forwards[ino] = s  # a reverse (-R) forward this session opened
        if inbound_ino is None:
            continue  # master listener or any process not tied to a session

        g = groups.get(inbound_ino)
        if g is None:
            g = {"inbound": inbound, "forwards": {}, "candidates": []}
            groups[inbound_ino] = g
        g["forwards"].update(forwards)
        g["candidates"].append({
            "pid": pid,
            "comm": info["comm"],
            "cmdline": info["cmdline"],
            "role": _classify_role(info["cmdline"]),
            "client_id": info.get("client_id"),
            "has_fwd": bool(forwards),
        })

    # Pick the representative process for each session: the worker. Prefer the
    # one actually holding forwards, then a "@user" worker title, then anything
    # that is not the monitor, then highest pid (worker forks after the monitor).
    role_rank = {"worker": 0, "other": 1, "preauth": 2, "listener": 3, "monitor": 4}
    child_idx = None  # built lazily only if a session needs the AcceptEnv path
    connections = []
    for g in groups.values():
        rep = min(
            g["candidates"],
            key=lambda c: (not c["has_fwd"], role_rank.get(c["role"], 1), -c["pid"]),
        )
        # clientID is inherited across the privsep fork, so any candidate that
        # has it is authoritative even if the chosen rep somehow lacks it.
        client_id = rep["client_id"]
        if client_id is None:
            for c in g["candidates"]:
                if c["client_id"] is not None:
                    client_id = c["client_id"]
                    break
        # Stock no-patch path: clientID delivered via AcceptEnv lands in the
        # session command's environ, a child of the worker. Look there next.
        if client_id is None:
            if child_idx is None:
                child_idx = _children_index()
            for pid in (c["pid"] for c in g["candidates"]):
                client_id = _client_id_from_children(pid, child_idx)
                if client_id:
                    break
        inbound = g["inbound"]
        connections.append({
            "pid": rep["pid"],
            "pids": sorted(c["pid"] for c in g["candidates"]),
            "comm": rep["comm"],
            "username": _user_from_cmdline(rep["cmdline"]),
            "client_id": client_id,
            "client_ip": inbound["remote_ip"],
            "client_port": inbound["remote_port"],
            "server_port": inbound["local_port"],
            "forwards": sorted(
                ({"bind_ip": f["local_ip"], "port": f["local_port"],
                  "family": f["family"]} for f in g["forwards"].values()),
                key=lambda x: x["port"],
            ),
        })

    # Stock-sshd fallback: for any connection still missing a clientID (no
    # proctitle/environ tag, i.e. unpatched sshd), recover it from the auth log
    # by joining on (client_ip, source_port). Only touched if needed, so patched
    # setups pay nothing and never read the journal.
    if any(c["client_id"] is None for c in connections):
        table = authlog.auth_table()
        id_map = authlog.load_id_map()
        for c in connections:
            if c["client_id"] is None:
                c["client_id"] = authlog.resolve(
                    c["client_ip"], c["client_port"], table=table, id_map=id_map
                )

    connections.sort(key=lambda c: (c["client_ip"], c["client_port"]))
    return {
        "ssh_ports": sorted(listener_ports),
        "privileged": os.geteuid() == 0,
        "permission_warning": denied and os.geteuid() != 0,
        "connections": connections,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(scan(), indent=2))
