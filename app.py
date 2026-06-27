"""
app.py - Web UI over the SSH reverse-forward scanner.

Endpoints
  GET  /                       -> dashboard
  GET  /api/connections        -> correlated inbound SSH conns + their forwards
  *    /proxy/{port}/{path}     -> best-effort HTTP reverse proxy to 127.0.0.1:port
  WS   /ws/ssh/{port}          -> asyncssh client to 127.0.0.1:port, bridged to xterm.js

Run:
  sudo python app.py --host 127.0.0.1 --port 8088
(root is needed to read other users' /proc/<pid>/fd; bind to loopback and reach
it over an SSH tunnel.)
"""

import os
import stat
import json
import base64
import asyncio
import argparse

import asyncssh
import httpx
import uvicorn
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, Response, FileResponse
from fastapi.staticfiles import StaticFiles

import scanner

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "static")

app = FastAPI(title="ssh reverse-forward inspector")
app.mount("/static", StaticFiles(directory=STATIC), name="static")

# Optional fallback private key for the terminal feature (PEM path).
SSH_CLIENT_KEY = os.environ.get("SSHRF_CLIENT_KEY")
# Override / extend autodetected sshd listen ports, e.g. SSHRF_SSH_PORTS=22,2200
_env_ports = os.environ.get("SSHRF_SSH_PORTS", "")
SSH_PORTS = [int(p) for p in _env_ports.split(",") if p.strip().isdigit()] or None

# Operator-assigned temporary clientIDs for connections that arrive without one.
# Keyed by "client_ip:client_port" (unique per live TCP connection); held in
# memory only and pruned when the connection goes away, so it is inherently
# temporary and resets on restart.
_manual_client_ids = {}


@app.get("/", response_class=HTMLResponse)
async def index():
    return FileResponse(os.path.join(STATIC, "index.html"))


@app.get("/api/connections")
async def api_connections():
    data = scanner.scan(ssh_ports=SSH_PORTS)
    live = {f"{c['client_ip']}:{c['client_port']}" for c in data["connections"]}
    # Drop overrides whose connection has gone away (keeps the map "temporary").
    for key in [k for k in _manual_client_ids if k not in live]:
        del _manual_client_ids[key]
    # An operator-set label wins over whatever was (or was not) auto-detected.
    for c in data["connections"]:
        label = _manual_client_ids.get(f"{c['client_ip']}:{c['client_port']}")
        if label:
            c["client_id"] = label
            c["client_id_manual"] = True
    return JSONResponse(data)


@app.post("/api/clientid")
async def set_clientid(request: Request):
    """Set (or clear, with an empty label) a temporary clientID for a live
    connection identified by its client_ip + client_port."""
    body = await request.json()
    ip = body.get("client_ip")
    port = body.get("client_port")
    label = (body.get("label") or "").strip()
    if not ip or port is None:
        return JSONResponse({"error": "client_ip and client_port required"},
                            status_code=400)
    key = f"{ip}:{port}"
    if label:
        _manual_client_ids[key] = label
    else:
        _manual_client_ids.pop(key, None)
    return JSONResponse({"ok": True, "label": label})


# ---------------------------------------------------------------- HTTP proxy
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-encoding",
    "content-length",
}


@app.api_route(
    "/proxy/{port:int}/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def proxy(port: int, path: str, request: Request):
    url = f"http://127.0.0.1:{port}/{path}"
    body = await request.body()
    fwd_headers = {
        k: v for k, v in request.headers.items() if k.lower() not in {"host"}
    }
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=False) as client:
            up = await client.request(
                request.method, url,
                params=request.query_params, content=body, headers=fwd_headers,
            )
    except httpx.HTTPError as exc:
        return Response(f"proxy error to 127.0.0.1:{port}: {exc}", status_code=502)

    out_headers = {
        k: v for k, v in up.headers.items() if k.lower() not in HOP_BY_HOP
    }
    return Response(content=up.content, status_code=up.status_code, headers=out_headers)


# ----------------------------------------------------- shared SSH auth / SFTP
def _build_connect_kwargs(port, auth):
    """asyncssh.connect kwargs for a loopback forward. Honors an optional
    per-session uploaded private key (PEM text + passphrase), else falls back to
    the server-wide SSHRF_CLIENT_KEY. Raises ValueError on a bad key so the
    caller can report it to the browser."""
    username = auth.get("username") or os.environ.get("USER")
    password = auth.get("password") or None
    kwargs = dict(host="127.0.0.1", port=port, username=username,
                  known_hosts=None)  # loopback forward: pinning adds nothing
    if password:
        kwargs["password"] = password

    pem = auth.get("private_key")
    if pem:
        passphrase = auth.get("key_passphrase") or None
        try:
            key = asyncssh.import_private_key(pem, passphrase)
        except Exception as exc:
            raise ValueError(f"could not load private key: {exc}")
        kwargs["client_keys"] = [key]  # uploaded key takes precedence
    elif SSH_CLIENT_KEY:
        kwargs["client_keys"] = [SSH_CLIENT_KEY]
    return kwargs


MAX_SFTP_BYTES = 25 * 1024 * 1024  # cap on in-memory file transfers


def _sftp_entry(name):
    perm = name.attrs.permissions or 0
    if stat.S_ISDIR(perm):
        typ = "dir"
    elif stat.S_ISLNK(perm):
        typ = "link"
    else:
        typ = "file"
    return {"name": name.filename, "type": typ,
            "size": name.attrs.size or 0, "mtime": name.attrs.mtime or 0}


@app.websocket("/ws/sftp/{port}")
async def ws_sftp(ws: WebSocket, port: int):
    """SFTP session over the same loopback forward the terminal uses. Auth is
    sent once as the first JSON frame; subsequent frames are {op, ...} requests
    (list/read/write/mkdir/remove/rmdir/rename)."""
    await ws.accept()
    try:
        auth = await ws.receive_json()
    except Exception:
        await ws.close()
        return
    try:
        connect_kwargs = _build_connect_kwargs(port, auth)
    except ValueError as exc:
        await ws.send_json({"type": "error", "message": str(exc)})
        await ws.close()
        return

    try:
        conn = await asyncssh.connect(**connect_kwargs)
    except Exception as exc:
        await ws.send_json({"type": "error", "message": f"connect to 127.0.0.1:{port} failed: {exc}"})
        await ws.close()
        return
    try:
        sftp = await conn.start_sftp_client()
    except Exception as exc:
        await ws.send_json({"type": "error", "message": f"sftp failed (is the far end an SSH server?): {exc}"})
        await ws.close()
        conn.close()
        return

    try:
        await ws.send_json({"type": "ready", "cwd": await sftp.realpath(".")})
        while True:
            req = await ws.receive_json()
            op = req.get("op")
            try:
                if op == "list":
                    path = await sftp.realpath(req.get("path") or ".")
                    entries = [_sftp_entry(n) for n in await sftp.readdir(path)
                               if n.filename not in (".", "..")]
                    entries.sort(key=lambda e: (e["type"] != "dir", e["name"].lower()))
                    await ws.send_json({"type": "list", "path": path, "entries": entries})
                elif op == "read":
                    path = req["path"]
                    async with sftp.open(path, "rb") as fh:
                        data = await fh.read(MAX_SFTP_BYTES + 1)
                    if len(data) > MAX_SFTP_BYTES:
                        raise ValueError(f"file exceeds {MAX_SFTP_BYTES // (1024 * 1024)} MB download cap")
                    await ws.send_json({"type": "file", "name": path.rsplit("/", 1)[-1],
                                        "data": base64.b64encode(data).decode()})
                elif op == "write":
                    raw = base64.b64decode(req["data"])
                    if len(raw) > MAX_SFTP_BYTES:
                        raise ValueError(f"file exceeds {MAX_SFTP_BYTES // (1024 * 1024)} MB upload cap")
                    async with sftp.open(req["path"], "wb") as fh:
                        await fh.write(raw)
                    await ws.send_json({"type": "ok", "op": "write", "path": req["path"]})
                elif op == "mkdir":
                    await sftp.mkdir(req["path"])
                    await ws.send_json({"type": "ok", "op": "mkdir", "path": req["path"]})
                elif op == "remove":
                    await sftp.remove(req["path"])
                    await ws.send_json({"type": "ok", "op": "remove", "path": req["path"]})
                elif op == "rmdir":
                    await sftp.rmdir(req["path"])
                    await ws.send_json({"type": "ok", "op": "rmdir", "path": req["path"]})
                elif op == "rename":
                    await sftp.rename(req["src"], req["dst"])
                    await ws.send_json({"type": "ok", "op": "rename"})
                else:
                    await ws.send_json({"type": "error", "message": f"unknown op {op!r}"})
            except Exception as exc:
                await ws.send_json({"type": "error", "op": op, "message": str(exc)})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        conn.close()


# ------------------------------------------------------------- SSH terminal
@app.websocket("/ws/ssh/{port}")
async def ws_ssh(ws: WebSocket, port: int):
    await ws.accept()
    try:
        auth = await ws.receive_json()
    except Exception:
        await ws.close()
        return

    cols = int(auth.get("cols", 80))
    rows = int(auth.get("rows", 24))
    try:
        connect_kwargs = _build_connect_kwargs(port, auth)
    except ValueError as exc:
        await ws.send_json({"type": "error", "data": str(exc)})
        await ws.close()
        return

    try:
        conn = await asyncssh.connect(**connect_kwargs)
    except Exception as exc:
        await ws.send_json({"type": "error", "data": f"connect to 127.0.0.1:{port} failed: {exc}"})
        await ws.close()
        return

    try:
        proc = await conn.create_process(
            term_type="xterm-256color", term_size=(cols, rows),
            stderr=asyncssh.STDOUT, encoding=None,  # raw bytes both ways
        )
    except Exception as exc:
        await ws.send_json({"type": "error", "data": f"shell failed: {exc}"})
        await ws.close()
        conn.close()
        return

    async def pump_stdout():
        try:
            while True:
                data = await proc.stdout.read(4096)
                if not data:
                    break
                await ws.send_bytes(data)
        except Exception:
            pass
        finally:
            try:
                await ws.close()
            except Exception:
                pass

    out_task = asyncio.create_task(pump_stdout())
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            # Binary frames are keystrokes; text frames are JSON control (resize).
            if msg.get("bytes") is not None:
                proc.stdin.write(msg["bytes"])
            elif msg.get("text") is not None:
                try:
                    ctrl = json.loads(msg["text"])
                except Exception:
                    proc.stdin.write(msg["text"].encode())
                    continue
                if ctrl.get("type") == "resize":
                    proc.change_terminal_size(int(ctrl["cols"]), int(ctrl["rows"]))
    except WebSocketDisconnect:
        pass
    finally:
        out_task.cancel()
        proc.close()
        conn.close()


def main():
    ap = argparse.ArgumentParser(description="SSH reverse-forward inspector")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (keep on loopback; default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8088, help="web UI port")
    args = ap.parse_args()
    if os.geteuid() != 0:
        print("WARNING: not running as root; you will only see your own sshd "
              "sessions' sockets. Re-run with sudo to inspect all users.")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
