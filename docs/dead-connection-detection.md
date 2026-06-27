# Detecting ungraceful disconnects faster

## The problem

When a tunneling client drops off the network *without* closing its SSH
connection — laptop sleeps, Wi-Fi dies, cell modem drops, power loss — the
TCP connection on the server stays `ESTABLISHED` from the kernel's point of
view. Nothing has sent a FIN or RST, so the socket simply sits there. The
inspector reads connection state from `/proc/net/tcp` (`scanner.py`), which
reflects exactly what the kernel believes, so the dead session keeps showing up
as a live forward for a long time.

How long? With no countermeasures, a silent peer can linger until the kernel's
own retransmission timeout gives up — `tcp_retries2` defaults to ~15
retransmits, which is on the order of **13–30 minutes**, and with zero unacked
data in flight it can be effectively forever. That is the lag you are seeing in
the UI.

The kernel keeps `ESTABLISHED` because, absent application keepalives or
in-flight data, there is nothing to retransmit and therefore nothing to time
out. The fix has two independent layers; do both.

---

## Layer 1 — make sshd reap dead sessions (the real fix, config only)

This is server-side sshd configuration and costs no code. It makes the
*session itself* go away quickly, which means the forward listener is torn
down and the inspector stops showing it on the next 8-second poll.

```
# /etc/ssh/sshd_config
ClientAliveInterval 15      # send an encrypted keepalive every 15s of quiet
ClientAliveCountMax 3       # give up after 3 unanswered (≈45s) and close
TCPKeepAlive yes            # also let the OS probe at the TCP layer
```

With this, a dead client is detected and its sshd worker exits in roughly
`Interval × CountMax` seconds (≈45s above). When the worker exits, the
reverse-forward LISTEN socket it owned closes, the `/proc` correlation drops
the session, and the UI clears it. Tune the numbers to taste: `15 × 3` is a
good responsiveness/overhead balance; `30 × 2` is gentler.

> This is the single highest-impact change. No app-side heuristic can make a
> truly half-open socket honest the way an application-level keepalive that
> actually closes the session can.

The client side helps too if you control it (and you do — see
`in-band-forward-control.md`): a `ServerAliveInterval`/`ServerAliveCountMax`
on the client, or the custom client sending its own keepalives, lets the client
notice a dead server symmetrically.

---

## Layer 2 — surface "suspect" sessions in the UI (app-side heuristic)

Even with Layer 1 there is a detection window (the `Interval × CountMax`
seconds before sshd gives up). During that window we can *flag* a connection as
probably-dead from data the kernel already exposes, so the operator sees a
warning sooner than the session actually disappears.

### Signal A — TCP-level state from `/proc/net/tcp`

`_read_net_tcp()` in `scanner.py` currently parses only columns 1, 2, 3 and 9
(local addr, remote addr, state, inode) and discards the rest. Two later
columns are exactly what we want:

- **`tx_queue`** (column 4, the part before the `:`) — bytes queued in the send
  buffer that the peer has not acknowledged. For an idle-but-healthy connection
  this is 0. A non-zero and *non-decreasing* `tx_queue` across polls means we
  are sending and getting no ACKs — a strong dead-peer signal.
- **`retransmits` / `timer`** (columns 5–6) — the retransmission timer slot and
  the number of unrecovered retransmits. A climbing retransmit count is the
  kernel actively failing to reach the peer.

These come for free in the same file we already read every 8 seconds; no extra
syscalls, no new sockets. Parse them, and mark a connection `suspect` when
`tx_queue > 0` with retransmits in progress.

### Signal B — richer detail from `ss -ti` (optional)

For a sharper read, shell out to `ss -tin` (or use the `sock_diag` netlink API)
for the inbound 4-tuple. It exposes `rto`, `unacked`, `retrans`, and
`lastrcv`/`lastack` (milliseconds since the last byte received/acked). A large
`lastrcv` combined with `unacked > 0` is high-confidence "this peer is gone."
This is more work and adds a subprocess per scan, so treat it as an enrichment
for flagged connections only, not the default path.

### Signal C — active liveness probe

For forwards that are SSH (we already detect this via the banner probe in
`scanner.py`), a periodic lightweight TCP connect + banner read to
`127.0.0.1:<forward_port>` confirms the tunnel still carries traffic end to
end. If the connect hangs or fails while the inbound socket still claims
`ESTABLISHED`, the session is almost certainly dead. This actually exercises
the data path rather than inferring from counters, but it costs a connection
through the tunnel, so cache aggressively (the existing `_SSH_PROBE_CACHE`
pattern) and only escalate to it for connections Signal A already flagged.

### Suggested implementation

1. Extend `_read_net_tcp()` to capture `tx_queue` and `retransmits`.
2. Carry them onto the inbound socket info and into each connection's JSON as
   `stale: bool` (true when `tx_queue > 0` and retransmits are advancing) plus
   the raw numbers for tooltip detail.
3. In the UI, render a red **"stale?"** pill on flagged connections, dim their
   card, and sort them to the **bottom** of the list so healthy sessions stay
   up top. Keep it advisory — the session is still shown until it actually
   closes; we are only saying "this one looks dead."

> Implemented: `scanner.py` parses `tx_queue`/`retransmits`, sets `stale` when
> both are non-zero, and sorts stale sessions last; the UI renders the pill and
> dims the card (`static/app.js`, `static/index.html`).
4. (Optional) Gate Signal C behind Signal A so the active probe only runs for
   already-suspect sessions.

### Limits to be honest about

- A genuinely idle, healthy connection sending no data has `tx_queue == 0` and
  no retransmits — indistinguishable at the TCP layer from a freshly-dead one
  until something tries to send. This is *why* Layer 1 matters: the keepalive
  is what forces a send and thus a detectable failure.
- The heuristic reduces *time-to-flag*, not *time-to-removal*. Removal still
  waits on sshd (Layer 1) or the kernel. Set expectations accordingly.
