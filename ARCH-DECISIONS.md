# Architecture decisions

Brief records of high-level design decisions in `obrien`. Newest last.

## 1. Use kettlingar-go for the daemon scaffolding

`obrien` is built on [kettlingar-go](https://github.com/mailpile/kettlingar-go),
which supplies process management (`obrien start`/`stop`), configuration
(flags, `OBRIEN_*` environment variables, `obrien.yaml`), metrics
(`obrien metrics`, OpenMetrics), logging, and a CLI that talks to the running
daemon over a local, authenticated RPC interface.

**Why:** these are needed by any long-running service and are not what this
project is about. kettlingar provides them in one place and makes it easy to
add new CLI commands as RPC methods on the daemon.

**How:** kettlingar is a git submodule in `submodules/kettlingar-go`, and a
`replace` directive in `go.mod` builds against that checkout, so changes to
kettlingar can be made and tested locally alongside `obrien`.

## 2. Proxy design

`obrien` is a security tool, not a load balancer: it forwards to a single
upstream service (one address per listener, see #6) so it can monitor and
filter the traffic sent there.

- **Built on the standard library.** `net/http` and `httputil.ReverseProxy`
  handle HTTP/1.1, HTTP/2 and TLS, keeping the dependency surface small.
- **Listeners.** Cleartext HTTP and TLS termination can run together; each is
  its own `http.Server` sharing one request pipeline. TLS is 1.2+ and offers
  HTTP/2.
- **Fail at start, not later.** Listeners are bound and certificates loaded in
  kettlingar's `ServiceStartup` hook, which runs before `obrien start` reports
  success, so a bad address or certificate fails the start command.
- **Request pipeline:** `monitor.Middleware` (hooks, in `monitor/`) → `rules.Filter`
  (inspection, in `rules/`) → `proxy.New` (forwarding, in `proxy/`). Deciding
  what traffic may pass is kept separate from moving it.
- **Performance.** Pooled keep-alive upstream connections, reused copy
  buffers, immediate flushing for streaming responses, and timeouts on both
  the client and upstream sides.
- **Transparency.** The client's `Host` header is forwarded unchanged, and
  `X-Forwarded-For`/`-Host`/`-Proto` are set.

## 3. The CLI only remote-controls the daemon

Every `obrien` command other than kettlingar's own `start`/`stop` is an RPC
method on the running daemon. Nothing is handled locally in the CLI process.

**Why:** the daemon is the one source of truth for its state (bound
listeners, loaded settings). A local command would have to guess that state
from flags and config, and could get it wrong or act while the daemon is down.

## 4. Standard ports via firewall redirect

obrien listens on unprivileged ports, and the `firewall-on` RPC method
installs nftables rules that redirect incoming TCP 80/443 to the ports the
daemon actually bound (`firewall-off` undoes it).

**Why:** the proxy never needs root, and redirection can be turned on and off
without restarting it. Using the bound listeners means the firewall can only
point at ports something is really listening on.

**How:** the daemon runs `sudo -n nft -f -`. All rules live in one nftables
table, `inet obrien` (IPv4 and IPv6), which is replaced or deleted
atomically, so obrien never edits rules it does not own. Incoming traffic is
redirected in the `prerouting` hook. Every rule matches only connections
addressed to this host (`fib daddr type local`): prerouting also sees traffic
routed through the host, such as containers or VMs connecting out to port
443, and that must never be redirected. With `--local true`, connections made
on the host are also redirected in the `output` hook. When either
listener's upstream is on a redirected port, packets from the daemon's uid
to that port are exempt there, because otherwise obrien's connections to a local upstream would be
redirected back into obrien. The uid is the only way the rule can tell those
apart, and it also exempts clients running as that user, so the exemption is
added only when it is needed.

## 5. Monitoring through hooks

`monitor.Middleware` summarises each request after its response as a
`Record` and passes it to a list of `Hook`s. Metrics and the request log are
both hooks.

**Why:** new kinds of monitoring (alerting, export, anomaly detection) can be
added without touching the proxy or the rules, and none of them needs to
know about HTTP handler wrapping.

**How:** hooks run synchronously after the response, so they don't delay
it, but they do hold the request's goroutine and must be fast. The request
log is a fixed-size ring buffer (`--request-log`, default 1000), so memory
use is bounded however much traffic passes, and old entries are simply
overwritten. It lives only in memory and is lost on restart.

## 6. Re-encrypting to the upstream web server

Each listener has its own upstream: the cleartext listener forwards to
`--upstream` (default `http://127.0.0.1:80`) and the TLS listener to
`--upstream-https` (default `https://127.0.0.1:443`). The defaults assume
obrien sits in front of a web server on the same host, whose ports the
firewall redirect intercepts (#4).

**Why:** the web server keeps serving its own ports and certificates
unchanged, and obrien can inspect HTTPS traffic because it terminates TLS
itself.

**How:** obrien dials the upstream address, but uses the client's SNI (or
`Host`) as the TLS server name and verifies the web server's certificate
against it. That name is put in the outgoing URL, so the transport's
connection pool is keyed on it, and a connection verified for one name is
never reused for another. Requests without a host name, or for a name the
web server's certificate doesn't cover, fail with 502.

Re-encryption is the default, but an `http://` `--upstream-https` forwards
TLS requests in cleartext (with `X-Forwarded-Proto: https`) to save the
second TLS session's CPU where the local hop is trusted. This uses the
existing setting rather than adding a flag, because the URL scheme already
says how to talk to the upstream.

## 7. Rules judge the raw header, and obrien parses it itself

Requests are filtered on the header bytes the client actually sent, not on
net/http's parsed view of them. Every request first passes a strict sanity
check: anything that fails to parse, or has ambiguous framing, is rejected.
Then a named, runtime-editable list of regular expressions is matched
against the raw header.

**Why:** an attack that relies on how a server parses a request is best
caught before parsing smooths it over: net/http canonicalises names,
merges and reorders fields, and tolerates some malformed input that the
upstream may read differently. Rejecting anything unparseable means a rule
can't be dodged by malformed syntax that the upstream reads differently.
Regular expressions are a quick way to answer a new advisory without
rebuilding obrien.

**How:** `rules.Listen` wraps each connection and follows its HTTP/1.x
framing itself to capture each header. Filter checks every captured header
against the request net/http produced, so if the two parsers ever disagree
about where a request starts, the request is rejected instead of being judged
on the wrong bytes. Since net/http only serves HTTP/2 and sets `Request.TLS`
for a bare `*tls.Conn`, `rules.Listen` also terminates TLS: HTTP/2
connections go through unwrapped and their headers are rebuilt from the
decoded request, which has no raw form. Patterns live in memory only and
are managed with the `rules-*` commands (#3), using `rules-list -f json`
output as the file format for `rules-add --file`.

## 8. Statically linked binaries

The Makefile builds with cgo disabled, so `obrien` is a single statically
linked binary.

**Why:** it can be copied onto older machines without depending on their
libc version. obrien needs nothing from cgo: DNS and user lookups fall back
to Go's own implementations.

## 9. Blocked requests link to an explanation

A request rejected by the rules gets an error status (`--blocked-status`,
default 502) with a minimal HTML page linking to a page that explains the
block. Each pattern may name its own URL, and `--blocked-url` is the default;
the rejection reason itself is still never sent to the client.

**Why:** legitimate users caught by a rule need somewhere to learn why and
what to do.

**How:** rules return a `rules.Rejection` error carrying the URL. URLs are
limited to http(s) or absolute paths and HTML-escaped, so a rule cannot
inject script into the page.
