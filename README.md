# ssh reverse-forward inspector

A small FastAPI tool that lists inbound SSH sessions on the local box, shows
which reverse (`-R`) port forwards each one created, and lets you **browse** to
a forwarded HTTP service or open a **web terminal** (vendored xterm.js) by
SSHing through the forwarded port with asyncssh.

## How the correlation works

Every inbound SSH session is handled by one per-session sshd worker process.
That single process holds **both** the ESTABLISHED socket to the client (local
port == the sshd listen port) **and** the LISTEN socket(s) it opened for each
`ssh -R` forward. The scanner walks `/proc/<pid>/fd` to get each sshd worker's
socket inodes, resolves those inodes against `/proc/net/tcp` and
`/proc/net/tcp6`, and joins them by PID. No heuristics, no guessing.

- ESTABLISHED, local port in the sshd listen set  -> the client connection
- LISTEN, local port *not* in the sshd listen set -> a reverse forward
- The master listener and the `[priv]` monitor have neither, so they drop out.

It detects classic `sshd` and OpenSSH >= 9.8 `sshd-session` workers, and
auto-detects the sshd listen port(s) from the master's `[listener]` process
(override with `SSHRF_SSH_PORTS=22,2200`).

## clientID

Each connection can carry a human-readable `clientID` (blue pill); connections
without one show an amber "no clientID" pill. The scanner resolves it from
several sources, in priority order, and any one of them is enough.

### 1. Stock sshd, no patch, no map (recommended)

Use OpenSSH's `AcceptEnv`. The client asserts a label; the server accepts it
with a single config line and no per-client state:

```
# /etc/ssh/sshd_config
AcceptEnv clientID
```

```bash
# client: note this does NOT use -N (see below); the keepalive gives the
# connection a session channel for the env var to ride on.
ssh -o SetEnv=clientID=edge-77 -R 5555:localhost:22 tun@server sleep infinity
```

The label lands in the environment of the session command (`sleep infinity`),
which sshd forks as a child of the per-session worker. The scanner walks the
worker's children (`/proc/<child>/environ`) and reads it there. Legacy clients
that omit `SetEnv` simply show "no clientID".

Why not `-N`: `-N` opens no session channel, and `AcceptEnv`/`SetEnv` deliver
the variable into the session channel's environment, so with `-N` there is
nothing to apply it to. The keepalive command provides that channel for the
cost of one tiny process per tunnel. (It must be read from the child, not the
worker: the worker's own `/proc/environ` never holds it, and is frozen at exec
time anyway.)

Caveat: an `AcceptEnv` label is client-asserted, so a client can claim any
clientID. Fine for a cooperative fleet; if you need it to be unspoofable, use
certificates below.

### 2. Stock sshd via SSH certificates (trustworthy, still no per-client map)

An SSH certificate authority signs each client key into a certificate that
embeds a human-readable identity, and the server trusts only the CA's public
key, so the "map" is a single file regardless of how many clients you have:

```bash
# one-time: make a CA keypair
ssh-keygen -t ed25519 -f ssh_user_ca -C "tunnel CA"

# per client: sign their existing public key, stamping the identity with -I
ssh-keygen -s ssh_user_ca -I edge-77 -n tun -V +52w client_ed25519.pub
#   -I edge-77  = the human-readable identity baked into the cert
#   -n tun      = principal (the login user the cert is valid for)
```

```
# /etc/ssh/sshd_config  -- trust the CA, nothing per-client
TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub
```

The client connects normally with its certificate (`-i client_ed25519` picks up
`client_ed25519-cert.pub` automatically). sshd logs the cert identity on every
connect (`Accepted publickey ... ID edge-77 (serial N) CA ...`), so it works
even with `-N`, and clients cannot forge each other's ID because it is signed.
`authlog.py` reads that identity from the journal/`auth.log` and joins it to the
live connection by (client ip, source port). No map file is required for certs;
an optional `SSHRF_CLIENTID_MAP` JSON can override or label raw-key fingerprints
if you ever want it.

### 3. Patched sshd (only if you do patch)

If you do modify sshd, the most robust surface is the worker's **process title**
via `setproctitle()`, e.g. `sshd-session: user@notty (clientID=edge-77)`. The
scanner reads `clientID` (`=` or `:` separated) from `/proc/<pid>/cmdline`,
which updates at runtime and works with `-N`. A `clientID` in the worker's
exec-time **environ** is also read as a fallback.

### Quick checks on the server

```bash
# AcceptEnv path: label on the session command child
sudo tr '\0' '\n' < /proc/<child_pid>/environ | grep -i clientID
# certificate path: identity in the auth log (works for -N)
journalctl -b -t sshd -t sshd-session -g 'Accepted .*ID ' -o cat | tail
# patched-title path
ps -o pid,args -C sshd-session | grep -i clientid
```

## Files

```
scanner.py     /proc correlation engine (run standalone: python scanner.py)
app.py         FastAPI: /api/connections, /proxy/{port}, ws /ws/ssh/{port}
authlog.py     optional: clientID from SSH-cert identity in the auth log
vendor.py      downloads xterm.js into static/vendor (run once)
static/        index.html, app.js, vendor/ (xterm.js + fit addon + css)
docs/          design notes: dead-connection detection, in-band forward control
```

## Setup (Debian 13 / trixie, no pip)

All dependencies are packaged upstream, so install them with apt and run
directly against the system interpreter. No venv, no pip, and no PEP 668
`--break-system-packages` dance.

```bash
sudo apt install python3-fastapi python3-uvicorn python3-asyncssh \
                 python3-httpx python3-websockets
sudo python3 app.py --host 127.0.0.1 --port 8088
```

`python3-websockets` is what uvicorn auto-detects to serve the terminal's
websocket; without it `/ws/ssh/...` will not work. The xterm.js assets are
already bundled in `static/vendor/`, so `vendor.py` is not needed unless you
want to re-pull or bump the version (and it uses only the Python stdlib, no
extra packages).

Optional performance extras (uvicorn runs fine without them):
`sudo apt install python3-uvloop python3-httptools`.

Root is required to read other users' `/proc/<pid>/fd` and `/proc/<pid>/environ`.
Without it you only see your own sessions and the UI shows a warning.

## Using it

- **browse**: opens `/proxy/<port>/` so the request originates from the server.
  Reverse forwards usually bind to the server's loopback, so a direct
  `host:port` link from your laptop would hit *your* machine, not the server.
  The built-in proxy is best-effort (good for simple pages and APIs; apps with
  absolute asset paths or websockets may need `GatewayPorts` + a direct link).
- **terminal**: prompts for credentials, then SSHes to
  `127.0.0.1:<forward_port>` and bridges a PTY shell to xterm.js. This is the
  natural fit for the common `ssh -R 2222:localhost:22` reverse-shell pattern,
  where the forward exposes an SSH server. You need valid credentials for
  whatever is on the far end; set `SSHRF_CLIENT_KEY=/path/to/key` to offer a
  server-wide key, or upload a per-session private key in the auth dialog (see
  below). The **terminal** and **files** actions only appear on forwards whose
  far end answered with an SSH banner (auto-detected and cached); other forwards
  offer **browse**.
- **files**: opens an SFTP file browser over that same SSH forward — list,
  download, upload, mkdir, delete. Uses the identical auth dialog as the
  terminal. Transfers are held in memory and capped at 25 MB per file.
- **private-key auth**: the auth dialog has a "use a private key instead"
  section — paste a PEM key (or load it from a file) plus an optional
  passphrase. The key is used for that one terminal/SFTP session only, kept in
  memory, and never written to disk. Keep the app behind a loopback tunnel
  (see "Lock it down"): the key rides the same WebSocket the password already
  uses.
- **set clientID**: a connection that shows "no clientID" can be given a
  temporary label — click the amber pill and type one. The label lives in the
  server's memory only, applies until that connection closes, and resets when
  the app restarts. (For durable, trustworthy identities use the AcceptEnv or
  certificate paths above.)

(term.js is abandoned; this vendors xterm.js, its maintained successor, with no
bundler step via the UMD builds.)

## Lock it down

This tool runs as root, reads every user's socket table, can proxy to and open
SSH sessions against loopback services. Treat it as privileged:

- Keep `--host 127.0.0.1`. Reach it over your own SSH tunnel:
  `ssh -L 8088:127.0.0.1:8088 you@server` then open `http://127.0.0.1:8088`.
- Do not expose it on a LAN/public interface without auth in front (e.g. an
  nginx reverse proxy with HTTP basic/OIDC).
- Loopback SSH connections use `known_hosts=None` (host-key pinning adds nothing
  for a forward that already terminates inside this box). Don't reuse this
  client config for non-loopback hosts.

## systemd unit (optional)

`/etc/systemd/system/sshrf-inspector.service`:

```ini
[Unit]
Description=SSH reverse-forward inspector
After=network.target

[Service]
Type=exec
WorkingDirectory=/opt/sshrforward
ExecStart=/usr/bin/python3 /opt/sshrforward/app.py --host 127.0.0.1 --port 8088
# root needed for cross-user /proc fd reads
User=root
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now sshrf-inspector
```
