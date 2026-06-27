"use strict";

const $ = (sel) => document.querySelector(sel);

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function isPublicBind(ip) {
  return ip !== "127.0.0.1" && ip !== "::1";
}

function fmtSize(n) {
  if (n < 1024) return `${n} B`;
  const u = ["KB", "MB", "GB", "TB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return `${n.toFixed(n < 10 ? 1 : 0)} ${u[i]}`;
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
    // SSH-only actions (terminal, files) appear only when the far end answered
    // with an SSH banner; "browse" is offered for everything else.
    const sshActs = f.ssh
      ? `<button class="btn" onclick="openAuth(${f.port}, '${esc(target)}', '${esc(c.username)}', 'terminal')">terminal</button>
         <button class="btn" onclick="openAuth(${f.port}, '${esc(target)}', '${esc(c.username)}', 'sftp')">files</button>`
      : `<button class="btn" onclick="browsePort(${f.port})">browse</button>`;
    return `<tr>
      <td><span class="${bindClass}">${esc(target)}</span></td>
      <td>${esc(f.family)}</td>
      <td>${f.ssh ? '<span class="ssh-yes">ssh</span>' : "LISTEN"}</td>
      <td class="acts">${sshActs}</td>
    </tr>`;
  }).join("");

  const table = fwds.length
    ? `<table>
         <tr><th>forward (server side)</th><th>family</th><th>state</th><th></th></tr>
         ${rows}
       </table>`
    : "";

  // clientID pill is clickable to assign/edit a temporary label.
  const cidArgs = `'${esc(c.client_ip)}', ${c.client_port}, '${esc(c.client_id || "")}'`;
  const cid = c.client_id
    ? `<span class="pill cid${c.client_id_manual ? " manual" : ""}" title="click to edit"
             onclick="setClientId(${cidArgs})">clientID ${esc(c.client_id)}${c.client_id_manual ? " ✎" : ""}</span>`
    : `<span class="pill cid-missing" title="click to set a temporary clientID"
             onclick="setClientId(${cidArgs})">no clientID — set</span>`;

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

/* ----------------------------------------------------------- clientID edit */
async function setClientId(ip, port, current) {
  const label = prompt(`Temporary clientID for ${ip}:${port}\n(blank clears it)`, current);
  if (label === null) return;
  try {
    await fetch("/api/clientid", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client_ip: ip, client_port: port, label: label.trim() }),
    });
  } catch (_) { /* ignore; next poll reflects state */ }
  load();
}

/* ----------------------------------------------------------- auth (shared) */
let authCtx = null; // {port, label, kind}

function openAuth(port, label, defaultUser, kind) {
  authCtx = { port, label, kind };
  $("#overlay").classList.add("on");
  $("#termbox").style.display = "none";
  $("#authmodal").style.display = "block";
  $("#authtitle").textContent =
    (kind === "sftp" ? "SFTP to " : "SSH to ") + label;
  $("#auth-user").value = defaultUser && defaultUser !== "?" ? defaultUser : "";
  $("#auth-pass").value = "";
  $("#auth-key").value = "";
  $("#auth-keypass").value = "";
  $("#auth-keyfile").value = "";
  $("#auth-user").focus();

  $("#auth-go").onclick = submitAuth;
  $("#auth-cancel").onclick = closeOverlay;
  $("#auth-pass").onkeydown = (e) => { if (e.key === "Enter") submitAuth(); };
}

function loadKeyFile(input) {
  const file = input.files && input.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => { $("#auth-key").value = reader.result; };
  reader.readAsText(file);
}

function submitAuth() {
  const creds = {
    username: $("#auth-user").value.trim(),
    password: $("#auth-pass").value,
    private_key: $("#auth-key").value.trim() || undefined,
    key_passphrase: $("#auth-keypass").value || undefined,
  };
  $("#authmodal").style.display = "none";
  if (authCtx.kind === "sftp") startSftp(authCtx.port, authCtx.label, creds);
  else startTerminal(authCtx.port, authCtx.label, creds);
}

/* ---------------------------------------------------------------- terminal */
let term, fitAddon, ws;

function startTerminal(port, label, creds) {
  $("#termbox").style.display = "flex";
  $("#termtitle").textContent = `ssh ${creds.username}@${label}`;

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
    ws.send(JSON.stringify({ ...creds, cols: term.cols, rows: term.rows }));
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

function closeOverlay() {
  window.removeEventListener("resize", doFit);
  if (ws) { try { ws.close(); } catch (_) {} ws = null; }
  if (term) { term.dispose(); term = null; }
  $("#overlay").classList.remove("on");
}

/* -------------------------------------------------------------------- sftp */
let sftpWs, sftpCwd;

function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function bytesToB64(bytes) {
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

function joinPath(dir, name) {
  return dir === "/" ? `/${name}` : `${dir}/${name}`;
}

function sftpSend(msg) {
  if (sftpWs && sftpWs.readyState === WebSocket.OPEN) sftpWs.send(JSON.stringify(msg));
}

function startSftp(port, label, creds) {
  $("#sftpoverlay").classList.add("on");
  $("#sftptitle").textContent = `sftp ${creds.username}@${label}`;
  $("#sftpbody").innerHTML = `<div class="empty">connecting…</div>`;

  const proto = location.protocol === "https:" ? "wss" : "ws";
  sftpWs = new WebSocket(`${proto}://${location.host}/ws/sftp/${port}`);
  sftpWs.onopen = () => sftpWs.send(JSON.stringify(creds));
  sftpWs.onmessage = (ev) => {
    let m;
    try { m = JSON.parse(ev.data); } catch (_) { return; }
    if (m.type === "ready") { sftpCwd = m.cwd; sftpSend({ op: "list", path: m.cwd }); }
    else if (m.type === "list") { sftpCwd = m.path; renderSftp(m); }
    else if (m.type === "file") { saveFile(m.name, m.data); }
    else if (m.type === "ok") { sftpSend({ op: "list", path: sftpCwd }); }
    else if (m.type === "error") { sftpError(m.message); }
  };
  sftpWs.onclose = () => {
    if ($("#sftpoverlay").classList.contains("on") && !$("#sftpbody").querySelector("table")) {
      $("#sftpbody").innerHTML = `<div class="empty">connection closed</div>`;
    }
  };
}

function sftpError(msg) {
  const bar = $("#sftperr");
  bar.textContent = msg;
  bar.style.display = "block";
  setTimeout(() => { bar.style.display = "none"; }, 6000);
}

function renderSftp(m) {
  $("#sftppath").textContent = m.path;
  const rows = m.entries.map((e) => {
    const isDir = e.type === "dir";
    const nameCell = isDir
      ? `<a href="#" onclick="sftpEnter('${esc(e.name)}');return false">${esc(e.name)}/</a>`
      : `<a href="#" onclick="sftpGet('${esc(e.name)}');return false">${esc(e.name)}</a>`;
    return `<tr>
      <td>${isDir ? "📁" : "📄"} ${nameCell}</td>
      <td class="num">${isDir ? "" : fmtSize(e.size)}</td>
      <td class="acts">
        <button class="btn" onclick="sftpDelete('${esc(e.name)}', ${isDir})">delete</button>
      </td>
    </tr>`;
  }).join("");
  $("#sftpbody").innerHTML = `<table class="sftp">
    <tr><th>name</th><th class="num">size</th><th></th></tr>
    ${rows || `<tr><td colspan="3" class="empty">empty directory</td></tr>`}
  </table>`;
}

function sftpEnter(name) { sftpSend({ op: "list", path: joinPath(sftpCwd, name) }); }
function sftpUp() { sftpSend({ op: "list", path: joinPath(sftpCwd, "..") }); }
function sftpRefresh() { sftpSend({ op: "list", path: sftpCwd }); }
function sftpGet(name) { sftpSend({ op: "read", path: joinPath(sftpCwd, name) }); }

function sftpDelete(name, isDir) {
  if (!confirm(`Delete ${isDir ? "directory" : "file"} ${name}?`)) return;
  sftpSend({ op: isDir ? "rmdir" : "remove", path: joinPath(sftpCwd, name) });
}

function sftpMkdir() {
  const name = prompt("New directory name:");
  if (!name) return;
  sftpSend({ op: "mkdir", path: joinPath(sftpCwd, name.trim()) });
}

function sftpUpload(input) {
  const file = input.files && input.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    const data = bytesToB64(new Uint8Array(reader.result));
    sftpSend({ op: "write", path: joinPath(sftpCwd, file.name), data });
  };
  reader.readAsArrayBuffer(file);
  input.value = "";
}

function saveFile(name, b64) {
  const blob = new Blob([b64ToBytes(b64)], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function closeSftp() {
  if (sftpWs) { try { sftpWs.close(); } catch (_) {} sftpWs = null; }
  $("#sftpoverlay").classList.remove("on");
}

$("#refresh").onclick = load;
$("#termclose").onclick = closeOverlay;
window.openAuth = openAuth;
window.browsePort = browsePort;
window.setClientId = setClientId;
window.loadKeyFile = loadKeyFile;
window.sftpEnter = sftpEnter;
window.sftpGet = sftpGet;
window.sftpDelete = sftpDelete;

load();
setInterval(load, 8000);
