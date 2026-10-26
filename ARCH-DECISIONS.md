# Architecture decisions

High-level design decisions in `obrien`. Newest last.

## 1. kettlingar-go for daemon scaffolding

[kettlingar-go](https://github.com/mailpile/kettlingar-go) supplies process
management (`start`/`stop`), configuration (flags, `OBRIEN_*`,
`obrien.yaml`), metrics, logging, and a CLI talking to the daemon over
local authenticated RPC.

**Why:** generic service plumbing, not this project's subject.

**How:** git submodule in `submodules/kettlingar-go`, used via `replace` in
`go.mod` so it can be changed alongside obrien.

## 2. Proxy design

A security tool, not a load balancer: one upstream per listener (#6), so
its traffic can be monitored and filtered.

- **Standard library:** `net/http` and `httputil.ReverseProxy` for
  HTTP/1.1, HTTP/2 and TLS; minimal dependencies.
- **Listeners:** cleartext and TLS can run together, each an `http.Server`
  on one pipeline. TLS 1.2+, offers HTTP/2. Defaults `:9080`/`:9443`; TLS
  starts whenever a certificate and key are set.
- **Fail at start:** listeners and certificates are set up in
  `ServiceStartup`, before `obrien start` reports success.
- **Pipeline:** `monitor.Middleware` → `rules.Filter` → `proxy.New`;
  deciding what passes is separate from moving it.
- **Performance:** pooled keep-alive upstream connections (per client
  with `--allow-pagekite`, #15), reused buffers,
  immediate flushing, client and upstream timeouts.
- **Transparency:** `Host` forwarded unchanged; `X-Forwarded-*` set.

## 3. The CLI only remote-controls the daemon

Every command besides kettlingar's `start`/`stop` is a daemon RPC.

**Why:** the daemon is the source of truth for its state; a local command
would guess from flags and config, and could act while the daemon is down.

## 4. Standard ports via firewall redirect

obrien listens on unprivileged ports; `firewall-on` prints a shell script
redirecting TCP 80/443 to the bound ports, `firewall-off` and
`firewall-status` print scripts removing and listing them. The operator
runs them as root; obrien does not.

**Why:** no root for the proxy, toggling without restart, doesn't impact
or rely on the host configuration in any way.

**How:** the daemon picks the tool: `/usr/sbin/nft` if present, else
`iptables` (plus `ip6tables` if found); `--mode nft|iptables` overrides.
With nft, rules live in table `inet obrien`, replaced or deleted
atomically in one `nft` call. With iptables, they live in nat chains
`OBRIEN-PRE`/`OBRIEN-OUT`, each with one jump from `PREROUTING`/`OUTPUT`;
not atomic. Either way obrien never edits rules it doesn't own. Redirection
is in `prerouting`, only for traffic to this host (`fib daddr type local`),
never routed traffic (containers, VMs). `--local true` also redirects in
`output`. If an upstream is on a redirected port, the daemon's uid is
exempt there to avoid loops; uid is the only distinguishing mark and also
exempts other processes of that user, so it is added only when needed.

## 5. Monitoring through hooks

`monitor.Middleware` summarises each request as a `Record` and passes it to
`Hook`s; metrics and the request log are hooks.

**Why:** new monitoring needs no changes to proxy or rules, and no handler
wrapping.

**How:** hooks run synchronously after the response, so they must be fast.
The request log is a fixed-size in-memory ring (`--request-log`, default
1000), bounded and lost on restart. It stores the formatted trace log
lines (#13), so `obrien requests` and `--trace-log` match exactly and one
parser handles both.

## 6. Re-encrypting to the upstream

The cleartext listener forwards to `--upstream` (`http://127.0.0.1:80`),
the TLS listener to `--upstream-https` (`https://127.0.0.1:443`): a web
server on the same host, behind the redirect (#4).

**Why:** the source web server keeps its ports and certificates; obrien
inspects HTTPS by terminating TLS.

**How:** obrien dials the upstream address but uses the client's SNI (or
`Host`) as TLS server name and verifies against it. That name is in the
outgoing URL, so pooled connections are keyed on it and never reused across
names. No name, or one the certificate doesn't cover: 502.

An `http://` `--upstream-https` forwards in cleartext (with
`X-Forwarded-Proto: https`) to save CPU on a trusted hop; the URL scheme
already says how, so no extra flag.

## 7. Rules judge the raw header, parsed by obrien

Requests are filtered on the header bytes sent, not net/http's view. A
strict sanity check rejects anything unparseable or ambiguously framed;
then a named, runtime-editable list of regexes is matched.

**Why:** The sanity check (using the go http parser) protects against
generic shenanigans. The regexes can be added/removed at runtime and
can see the whole header at once, for speed/simplicity.

**How:** `rules.Listen` follows HTTP/1.x framing itself to capture each
header; Filter checks it against net/http's request and rejects on
disagreement. Since net/http only serves HTTP/2 and sets `Request.TLS` on a
bare `*tls.Conn`, `rules.Listen` also terminates TLS; HTTP/2 passes
unwrapped and its header is rebuilt. Patterns are memory-only, managed by
`rules-*` (#3); `rules-list -f json` is the `rules-add --file` format.

## 8. Static binaries

Built with cgo disabled.

**Why:** runs on old machines regardless of libc; DNS and user lookups fall
back to Go's own.

## 9. Blocked requests link to an explanation

Rejections get `--blocked-status` (502) and a minimal HTML page linking to
the rule's URL or `--blocked-url`. The reason is never sent.

**Why:** If we start blocking things, we owe legit users an explanation
when we make a mistake.

**How:** `rules.Rejection` carries the URL. URLs are http(s) or absolute
paths, HTML-escaped, so rules cannot inject script.

## 10. X-Forwarded-For trusted only from listed proxies

A client's `X-Forwarded-For` is replaced by its address unless it is in
`--trusted-proxies`, whose chains are kept with their address appended.

**Why:** the header is trivially spoofed, but behind another proxy the
upstream needs the real client.

**How:** only the direct peer is checked. `X-Forwarded-Host`/`-Proto`
always describe obrien's listener.

## 11. OWASP Core Rule Set through Coraza

`--crs block|detect` adds a rule running the CRS with
[Coraza](https://github.com/corazawaf/coraza), after sanity and patterns.

**Why:** broad, maintained attack signatures obrien's patterns can't match;
Coraza is pure Go, keeping the binary static (#8).

**How:** Coraza is a submodule with `replace` (#1); the CRS is embedded
from `coraza-coreruleset`. Exception to #7: it judges the parsed request,
but only after the raw sanity check. Up to 1 MiB of body is buffered,
inspected and passed on unchanged; larger bodies are inspected in part,
not refused. Responses aren't inspected. Coraza always blocks internally;
obrien decides whether to block or log, so detect reports exactly what
block would reject.

## 12. Request traces, tokenized as a stream

Requests carry a trace: tokens giving their shape (path, query, selected
headers, body structure), not content. Syntax:
[`trace/README.md`](trace/README.md).

**Why:** to map a site's expected traffic. Collecting traces and deriving
patterns later keeps analysis out of the request path.

**How:** the body is tokenized as the proxy streams it, via a
`Request.Body` wrapper, never buffered whole. The rest comes from the raw
header the rules judged (#7), passed back via a request-context slot.
Unread bodies (e.g. rejected requests) aren't traced. Traces are built only
when the request log or trace log (#13) is on.

Bodies are traced as files: the whole body, or each multipart part.

- JSON and XML (what APIs carry) are parsed from their first 20 KiB; a file
  cut short is repaired by closing what is open, and marked `TRUNC`.
- JSON keys are sorted so key order doesn't change traces; lists keep
  order, which usually matters.
- Types are sniffed, since API clients mislabel them.
- Other files: sniffed type and a coarse size only.
- Caps: 16 multipart parts, 64 form or query pairs, 10 words per value,
  each followed by `MORE` or `REST-`, so a trace is bounded.
- Only the first 512 bytes of a file (for sniffing) and the current file's
  tokens are held; keys can't be sorted before an object ends.

Only 2xx/3xx/4xx responses get a trace. Redirects count as normal use (POST
then 302, 304 revalidation); 4xx shows what clients ask for that the site
rejects, including blocks when `--blocked-status` is 4xx. 5xx says nothing
about the request, so is left out. The log still lists every request.

## 13. Traces also go to a plain-text log

`--trace-log PATH` appends one line per request: a Common Log Format line
(no byte count), host and trace, or `NOTRACE`. Requests obrien rejected
itself have `BLOCKED` before the trace, so their status isn't mistaken for
the upstream's; `BLOCKED MALFORMED` if the header sanity check rejected
them, separating broken clients and smuggling attempts from policy blocks.

**Why:** the request log (#5) is bounded and volatile; mapping traffic
needs long collection. An access-log shape suits existing tools, and
`NOTRACE` keeps the file complete while `grep -v NOTRACE` drops untraced
lines.

**How:** a monitor hook writing each line under a mutex with `O_APPEND`,
unbuffered, so lines aren't lost or split on a crash. Off by default.

After 20 MB written, the file is renamed with a `.YYYYMMDD-HHMMSS` suffix
and a new one opened; old files are never pruned, as collection should not
silently lose data. Bytes already in the file at start don't count.

## 14. TLS certificates reload themselves

Certificate files are re-read when their mtime or size changes, and
`--tls-keys` directories rescanned, at most once a minute, from
`tls.Config.GetCertificate`.

**Why:** renewals (e.g. Let's Encrypt) and new PageKite kites shouldn't
need a restart, and handshakes shouldn't each hit the filesystem.

**How:** one handshake per interval checks; others use the cached index. A
file that fails to load (e.g. cert and key mid-replacement) keeps its old
certificate, is logged once, and is retried when it changes. No checks
happen without traffic.

## 15. PageKite and CONNECT tunnelled unmodified, opt-in

With `--allow-pagekite`, connections whose first line is `CONNECT `,
`PING `, or a GET to a PageKite WebSocket tunnel path are passed to the
upstream as opaque byte streams, uninspected and unmodified.

**Why:** so obrien can front a PageKite relay. Its back-ends' tunnels and
probes aren't web requests, and the WebSocket handshake lacks the `Host`
header net/http requires. Opt-in, as it lets traffic past every rule.

**How:** `rules.Listen` reads the first line before net/http (or any
rule) sees the connection; matches go to `proxy.Tunnel`, which replays the
bytes read and copies both ways. A crude prefix test; the relay decides
what is valid. Only the first request on a connection is checked, as relays
do. Tunnels aren't requests: no record, trace or log line, only
`proxy_tunnels_total` and a log entry. TLS to the upstream uses the
client's SNI (#6). HTTP/2 connections are never diverted.

TLS for SNI names no certificate covers (#16) is passed still encrypted to
`--upstream-https`'s address: the relay serves those kites end to end.
The ClientHello is read by aborting a handshake and replayed. Connections
without SNI are terminated with the default certificate.

The relay routes each connection by its first request, so upstream
connections belong to one client connection: reused for its requests,
never another client's (#2), closed when it closes. HTTP/2 is off on both
sides: clients are offered only `http/1.1` by ALPN, as one HTTP/2
connection may carry several sites.

## 16. Multiple certificates, chosen by SNI

`--tls-keys` adds combined PEM files (chain and key, as PageKite uses), or
directories of them, beside the `--cert`/`--key` pair.

**Why:** a relay serves many names, often with wildcards; one file per
certificate means nothing to pair up.

**How:** certificates are indexed by their DNS names (the CN if none):
exact match, then a wildcard one label up, preferring one the client
supports (ECDSA/RSA), then the default (the pair, else the first loaded).
Every file in a directory is tried; ones without `-----BEGIN ` or over
1 MiB are silently skipped, other failures logged. Startup fails if the
pair fails or nothing loads.
