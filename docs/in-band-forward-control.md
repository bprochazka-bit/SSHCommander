# Rough spec: adding reverse forwards to a live connection (in-band)

## Goal

From the inspector UI, add (or remove) a reverse port forward on an
**already-established** connection, on demand, with these client-side
constraints:

- **No new socket** on the client — reuse the existing SSH transport.
- **No filesystem artifacts** on the client — no control socket, no temp files.
- Works with a **custom SSH client** we control (so we are free to add a
  protocol mechanism the stock OpenSSH client does not have).

## Why the server can't do it alone

In SSH, reverse (`-R`) forwards are always **requested by the client**: the
client sends a `tcpip-forward` global request and the server starts listening.
There is no message that lets the server tell an existing session "now also
listen on port X." So adding a forward mid-connection fundamentally requires the
client to act. The design below gives the UI a way to *signal* the custom
client to take that action, entirely in-band over the connection that already
exists.

## The two protocol facts this is built on

1. **`tcpip-forward` can be sent at any time.** It is a connection-protocol
   global request, not a setup-only handshake step. A custom client can emit a
   fresh `tcpip-forward` (or `cancel-tcpip-forward`) over the existing transport
   whenever it wants. The server opens the new listener and — because that
   listener is owned by the same per-session sshd worker — the inspector's
   `/proc` correlation picks it up automatically on the next poll. **No new
   socket, no files**: it's one more protocol message on the wire we already
   have.

2. **The session command runs server-side and its stdio is piped to the
   client over the existing channel.** This is the same mechanism the README's
   clientID pattern already relies on (`ssh ... tun@server sleep infinity`). If
   we replace that keepalive command with a small **server-side control agent**,
   its stdout flows back to the client through the session channel — giving us a
   server→client signaling path with zero extra client sockets and zero client
   files.

Putting those together: the inspector talks to a server-side agent; the agent's
stdout rides the existing channel to the custom client; the client turns those
instructions into `tcpip-forward` requests on the same connection.

```
  ┌────────── server box (this tool runs here) ──────────┐         client box
  │                                                       │
  │  inspector (FastAPI)                                  │
  │      │  local IPC (loopback or abstract unix socket)  │
  │      ▼                                                │
  │  sshrf-agent  ── stdout ─┐                            │
  │  (session command,       │   existing SSH session     │
  │   child of sshd worker)  └──── channel ───────────────┼──►  custom SSH client
  │                                                       │        │
  │  sshd worker ◄──── tcpip-forward (NEW) ───────────────┼────────┘
  │      │                                                │
  │      ▼  opens new LISTEN on 127.0.0.1:<port>          │
  │  scanner picks it up via /proc on next poll           │
  └───────────────────────────────────────────────────────┘
```

## Components

### 1. Custom client — channel reader + forward emitter

- On connect, in addition to the reverse forward(s) it sets up normally, open
  **one session channel** running the agreed control command (e.g. request exec
  of `sshrf-agent`). This channel replaces the `sleep infinity` keepalive and
  doubles as the clientID carrier (`SetEnv clientID=...` still works on it).
- Read **newline-delimited JSON** from that channel's stdout. For each command:
  - `add-forward` → send a `tcpip-forward` global request with the requested
    bind address/port; on the resulting forwarded-connection, dial the local
    target and splice (standard `-R` behavior the client already implements).
  - `cancel-forward` → send `cancel-tcpip-forward` for that bind/port.
  - `ping` → reply `pong` (liveness; see disconnect-detection doc).
- Optionally write **status JSON back** on the channel's stdin (client→agent),
  e.g. `{"op":"forward-result","port":5555,"ok":true}` or an error string. The
  agent relays it to the inspector.
- The client is the **policy enforcement point**: it decides whether to honor a
  request (allowed bind addresses, port ranges, target hosts). The server can
  only *ask*.

### 2. Server-side agent — `sshrf-agent`

- Is the session command sshd execs for the connection (so it is a child of the
  worker, exactly where the scanner already looks for the clientID environ).
- On startup, register with the inspector over **loopback HTTP** or an **abstract
  unix socket** (Linux abstract namespace → no filesystem path, satisfying the
  "no files" preference even on the server side). Identify itself by something
  the inspector can correlate — simplest is to print/registers its own PID and
  let the inspector map worker→child via `/proc`, or pass `clientID` through.
- Bridge: inspector → agent (over that IPC) → **stdout** (→ client). And
  client → **stdin** → agent → inspector for status. The agent is a dumb relay;
  all logic lives in the inspector and the client.

### 3. Inspector (this app) — UI + routing

- New endpoint, e.g. `POST /api/forward` with
  `{client_ip, client_port, bind_ip, bind_port, dest_host, dest_port}` and a
  matching `DELETE`.
- Resolve the target connection → its agent instance (via the
  worker→child→registration mapping) → hand it the JSON command.
- UI: an **"add forward"** button on each connection that has an active agent;
  a small form for bind port + target host:port; a remove control on each
  forward row. Surface the client's `forward-result` so failures (port in use,
  policy denied) show up instead of silently doing nothing.
- Forwards opened this way need no special teardown: they are owned by the sshd
  worker, so when the connection drops they close with it and the scanner clears
  them — same lifecycle as any `-R` forward.

## Message shapes (rough)

Server→client (one JSON object per line on the channel):

```json
{"op": "add-forward",    "bind_ip": "127.0.0.1", "bind_port": 5555, "dest_host": "localhost", "dest_port": 22, "id": "f1"}
{"op": "cancel-forward", "bind_ip": "127.0.0.1", "bind_port": 5555, "id": "f1"}
{"op": "ping", "id": "p7"}
```

Client→server (status, on the channel's stdin):

```json
{"op": "forward-result", "id": "f1", "ok": true,  "bound_port": 5555}
{"op": "forward-result", "id": "f1", "ok": false, "error": "policy: bind_port 5555 not allowed"}
{"op": "pong", "id": "p7"}
```

(`bound_port` lets the client report the actual port when `bind_port: 0` asks
the server to pick one.)

## Open questions to settle before building

- **Agent ↔ inspector transport:** abstract unix socket (no files, simplest) vs.
  loopback HTTP/WebSocket (agent dials the inspector; trivial but a server-side
  socket). The client constraints don't apply here; pick whichever is cleaner.
- **Correlation key:** how the inspector maps a UI connection to the right agent
  instance. Reusing `clientID` (already plumbed) or the worker→child PID link is
  the obvious candidate.
- **Authorization:** the client must validate requests (bind/target allowlists).
  Decide whether the inspector also gates who can add forwards (it runs as root;
  it should).
- **Bidirectional framing:** confirm the custom client cleanly multiplexes
  "control JSON" on the session channel without disturbing the clientID/keepalive
  role it already plays — or use a distinct channel/subsystem name for control.
- **`bind_port: 0`:** support server-assigned ports and report the chosen port
  back via `forward-result`.

## Why this satisfies the constraints

- **No new client socket:** every byte travels over the one existing SSH
  connection — the control channel (session channel) and the `tcpip-forward`
  requests share the same transport.
- **No client filesystem:** the client only reads its channel and emits protocol
  messages; nothing is written to disk. (Server-side state can be kept in an
  abstract unix socket if you want the server clean too.)
- **No sshd patch:** this rides stock OpenSSH server behavior — session command
  stdio plus standard `tcpip-forward`. All the new logic is in the custom client
  and our own agent/inspector.
