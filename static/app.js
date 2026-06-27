"use strict";

const $ = (sel) => document.querySelector(sel);

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function isPublicBind(ip) {
  return ip !== "127.0.0.1" && ip !== "::1";
}

async function load() {
  let data;
  try {
    const r = await fetch("/api/connections");
    data = await r.json();
  } catch (e) {
    $("#list").innerHTML = `<div class="empty">failed to load: ${esc(e)}</div>`;
    return;
  }

  $("#meta").textContent =
    `listening on :${data.ssh_ports.join(", :")} · ` +
    `${data.connections.length} session(s) · ` +
    (data.privileged ? "root" : "unprivileged");

  const warn = $("#warn");
  if (data.permission_warning) {
    warn.style.display = "block";
    warn.textContent =
      "Not running as root: some sshd sockets are hidden. Re-run with sudo to see all sessions.";
  } else {
    warn.style.display = "none";
  }

  const list = $("#list");
  if (!data.connections.length) {
    list.innerHTML = `<div class="empty">no inbound SSH sessions detected</div>`;
    return;
  }

  list.innerHTML = data.connections.map(renderConn).join("");
}

function renderConn(c) {
  const fwds = c.forwards;
  const tag = fwds.length
    ? `<span class="pill fwd">${fwds.length} reverse forward${fwds.length > 1 ? "s" : ""}</span>`
    : `<span class="pill nofwd">no forwards</span>`;

  const rows = fwds.map((f) => {
    const bindClass = isPublicBind(f.bind_ip) ? "bind-public" : "";
    const target = `${f.bind_ip}:${f.port}`;
    return `<tr>
      <td><span class="${bindClass}">${esc(target)}</span></td>
      <td>${esc(f.family)}</td>
      <td>LISTEN</td>
      <td class="acts">
        <button class="btn" onclick="browsePort(${f.port})">browse</button>
        <button class="btn" onclick="openTerminal(${f.port}, '${esc(target)}', '${esc(c.username)}')">terminal</button>
      </td>
    </tr>`;
  }).join("");

  const table = fwds.length
    ? `<table>
         <tr><th>forward (server side)</th><th>family</th><th>state</th><th></th></tr>
         ${rows}
       </table>`
    : "";

  const cid = c.client_id
    ? `<span class="pill cid">clientID ${esc(c.client_id)}</span>`
    : `<span class="pill cid-missing">no clientID</span>`;

  return `<div class="conn">
    <div class="conn-head">
      <span class="client">${esc(c.client_ip)}:${c.client_port}</span>
      ${cid}
      <span class="pill">user ${esc(c.username)}</span>
      <span class="pill">pid ${c.pid}</span>
      <span class="pill">${esc(c.comm)}</span>
      <span class="pill">&rarr; :${c.server_port}</span>
      ${tag}
    </div>
    ${table}
  </div>`;
}

// "browse": open the proxy endpoint so the request originates from the server
// (the forward is usually bound to the server's loopback).
function browsePort(port) {
  window.open(`/proxy/${port}/`, "_blank");
}

/* ---------------------------------------------------------------- terminal */
let term, fitAddon, ws;

function openTerminal(port, label, defaultUser) {
  $("#overlay").classList.add("on");
  $("#termbox").style.display = "none";
  $("#authmodal").style.display = "block";
  $("#authtitle").textContent = `SSH to ${label}`;
  $("#auth-user").value = defaultUser && defaultUser !== "?" ? defaultUser : "";
  $("#auth-pass").value = "";
  $("#auth-user").focus();

  $("#auth-go").onclick = () => startTerminal(port, label);
  $("#auth-cancel").onclick = closeTerminal;
  $("#auth-pass").onkeydown = (e) => { if (e.key === "Enter") startTerminal(port, label); };
}

function startTerminal(port, label) {
  const username = $("#auth-user").value.trim();
  const password = $("#auth-pass").value;
  $("#authmodal").style.display = "none";
  $("#termbox").style.display = "flex";
  $("#termtitle").textContent = `ssh ${username}@${label}`;

  term = new Terminal({
    fontFamily: 'ui-monospace, Menlo, Consolas, monospace',
    fontSize: 13, cursorBlink: true,
    theme: { background: "#000000", foreground: "#d6dde6" },
  });
  fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  term.open($("#term"));
  fitAddon.fit();

  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/ws/ssh/${port}`);
  ws.binaryType = "arraybuffer";

  ws.onopen = () => {
    ws.send(JSON.stringify({ username, password, cols: term.cols, rows: term.rows }));
    term.focus();
  };
  ws.onmessage = (ev) => {
    if (ev.data instanceof ArrayBuffer) {
      term.write(new Uint8Array(ev.data));
    } else {
      try {
        const m = JSON.parse(ev.data);
        if (m.type === "error") term.write(`\r\n\x1b[31m[${m.data}]\x1b[0m\r\n`);
      } catch (_) { /* ignore */ }
    }
  };
  ws.onclose = () => term && term.write("\r\n\x1b[90m[connection closed]\x1b[0m\r\n");

  term.onData((d) => {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(new TextEncoder().encode(d));
  });

  window.addEventListener("resize", doFit);
}

function doFit() {
  if (!fitAddon) return;
  fitAddon.fit();
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
  }
}

function closeTerminal() {
  window.removeEventListener("resize", doFit);
  if (ws) { try { ws.close(); } catch (_) {} ws = null; }
  if (term) { term.dispose(); term = null; }
  $("#overlay").classList.remove("on");
}

$("#refresh").onclick = load;
$("#termclose").onclick = closeTerminal;
window.openTerminal = openTerminal;
window.browsePort = browsePort;

load();
setInterval(load, 8000);
