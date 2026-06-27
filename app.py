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
import json
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


@app.get("/", response_class=HTMLResponse)
async def index():
    return FileResponse(os.path.join(STATIC, "index.html"))


@app.get("/api/connections")
async def api_connections():
    return JSONResponse(scanner.scan(ssh_ports=SSH_PORTS))


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


# ------------------------------------------------------------- SSH terminal
@app.websocket("/ws/ssh/{port}")
async def ws_ssh(ws: WebSocket, port: int):
    await ws.accept()
    try:
        auth = await ws.receive_json()
    except Exception:
        await ws.close()
        return

    username = auth.get("username") or os.environ.get("USER")
    password = auth.get("password") or None
    cols = int(auth.get("cols", 80))
    rows = int(auth.get("rows", 24))

    connect_kwargs = dict(host="127.0.0.1", port=port, username=username,
                          known_hosts=None)  # loopback forward: pinning adds nothing
    if password:
        connect_kwargs["password"] = password
    if SSH_CLIENT_KEY:
        connect_kwargs["client_keys"] = [SSH_CLIENT_KEY]

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
