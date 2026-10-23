# obrien

A reverse HTTP proxy that **monitors and filters** requests to a single
upstream. A security tool, not a load balancer.

## Features

- Cleartext HTTP and/or TLS termination (HTTP/1.1, HTTP/2).
- Forwards allowed requests to one upstream per listener, re-encrypting
  TLS, keeping `Host`, setting `X-Forwarded-For`/`-Host`/`-Proto`.
- Monitoring hooks: metrics and a bounded in-memory request log
  (`obrien requests`). 2xx/3xx requests get a trace of their shape (path,
  query, selected headers, body structure), not content. `--trace-log`
  appends every request to a file as an access-log line with its trace or
  `NOTRACE`.
- A strict header sanity check (well-formed, unambiguous framing).
- Runtime-editable named regexes on the raw header (`rules-add`,
  `rules-rm`, `rules-list`).
- Optional [OWASP CRS](https://coreruleset.org/) via
  [Coraza](https://coraza.io/), including up to 1 MiB of body:
  `--crs block` or `--crs detect` (log only).

## Layout

- `main.go`, `obrien.go`: the daemon: settings, listeners, TLS, metrics,
  wiring.
- `firewall.go`: `firewall-*` RPCs (nftables redirect of 80/443).
- `requests.go`: `requests` RPC (the request log).
- `rules_api.go`: `rules-*` RPCs (header patterns).
- `certs.go`: TLS key pair, reloaded when its files change.
- `annotator_test.go`: only 2xx/3xx requests get traces.
- [`proxy/`](proxy/README.md): forwarding.
- [`monitor/`](monitor/README.md): hooks and the request log.
- [`rules/`](rules/README.md): inspection and filtering.
- [`trace/`](trace/README.md): request traces.
- [`ARCH-DECISIONS.md`](ARCH-DECISIONS.md): design decisions.

## Build

[kettlingar-go](https://github.com/mailpile/kettlingar-go) (daemon, config,
metrics, logging, CLI) and [Coraza](https://github.com/corazawaf/coraza)
are submodules in `submodules/`, built via `replace` in `go.mod`, so local
edits take effect on the next build. The CRS is embedded from the
`coraza-coreruleset` module.

```sh
git submodule update --init   # fresh clone only
make                          # static binary (cgo off); e.g. make GOARCH=arm64
```

Pushing a `v*` tag runs `.github/workflows/release.yml`: tests, then a
release with linux amd64/arm64 binaries and SHA-256 sums. Requires Go
1.26+ (fetched automatically with `GOTOOLCHAIN=auto`).

## Usage

```sh
obrien start                 # cleartext on :9080 -> 127.0.0.1:80
obrien start --cert cert.pem --key key.pem   # also HTTPS on :9443
obrien firewall-on           # redirect 80/443 with nft
obrien metrics               # OpenMetrics: proxy_*, rules_*, monitor_*
obrien requests --count 20   # recent requests
obrien rules-list
obrien firewall-off
obrien stop
```

`start` returns once listeners are bound, failing on a bad address or
certificate; `--foreground` (`-F`) stays attached. `obrien --help` with the
daemon up lists every command.

| Setting      | Default                 | Description                          |
|--------------|-------------------------|--------------------------------------|
| `--upstream` | `http://127.0.0.1:80`   | Cleartext listener's upstream |
| `--upstream-https` | `https://127.0.0.1:443` | TLS listener's upstream; `http://` forwards cleartext |
| `--http`     | `:9080`                 | Cleartext address, or `off` |
| `--https`    | `:9443`                 | TLS address, or `off`; needs `--cert` and `--key` |
| `--cert`     | `off`                   | TLS certificate (PEM); changes picked up within a minute |
| `--key`      | `off`                   | TLS private key (PEM) |
| `--request-log` | `1000`               | Requests kept in memory; `0` disables |
| `--trace-log`   | `off`                | Absolute path of the trace log file |
| `--crs`      | `off`                   | OWASP CRS: `block`, `detect` or `off` |
| `--crs-paranoia` | `1`                 | CRS paranoia level, 1-4 |
| `--crs-conf` | `off`                   | Absolute path of extra CRS directives |
| `--trusted-proxies` | `off`            | IPs/CIDRs whose `X-Forwarded-For` is kept |
| `--blocked-status` | `502`             | Status for blocked requests (400-599) |
| `--blocked-url` | `off`                | Default explanation page linked from blocks |

Settings also come from `OBRIEN_<NAME>` variables (e.g. `OBRIEN_UPSTREAM`)
or `obrien.yaml` in the user config directory (`~/.config/kettlingar/`).

### Filtering requests

Headers that don't parse strictly or have ambiguous framing (e.g. duplicate
`Content-Length`, or it with `Transfer-Encoding`) are rejected and counted
in `rules_invalid_total`.

The raw header (request line, fields, CRLFs) is then matched against named
[Go regexes](https://pkg.go.dev/regexp/syntax); any match rejects.
`rules_matched_total{rule="NAME"}` and `rules-list` count matches per name,
kept across replacement, reset on restart. HTTP/2 headers are matched as
rebuilt HTTP/1 text, fields sorted by name.

```sh
obrien rules-add multipart '(?im)^content-type:\s*multipart/'
obrien rules-add --replace multipart multipart '(?im)^content-type:\s*multipart/form-data'
obrien rules-add --url https://example.com/blocked.html upload '(?im)^content-type:\s*multipart/'
obrien rules-rm multipart
obrien rules-list -f json > rules.json
obrien rules-add --file "$PWD/rules.json"  # absolute path: the daemon reads it
```

Use `(?i)` and `(?m)`; lines end in `\r\n`, so `$` sees the `\r`. Patterns
live in memory only.

Blocked requests get `--blocked-status` and a short HTML page linking to the
first matching rule's `--url`, else `--blocked-url`, else nothing. URLs must
be `http(s)://` or an absolute path.

### In front of a web server on 80 and 443

By default obrien forwards to `127.0.0.1:80` and `:443`, where the web
server stays, and the firewall redirects incoming 80/443 to obrien:

```sh
obrien start --cert cert.pem --key key.pem
obrien firewall-on               # 80 -> 9080, 443 -> 9443
obrien firewall-on --local true  # also redirect local connections
obrien firewall-status           # rules and kernel counters
obrien firewall-off
```

Redirects target the ports actually bound by running listeners, so the
daemon must be up. It runs `sudo -n nft` (needs passwordless sudo for
`nft`). Rules live in table `inet obrien` only, and survive daemon stop.

Only connections addressed to this host are redirected, not routed traffic
(containers, VMs). By default only traffic from other hosts is; a
loopback-only listener is refused. With `--local true`, local connections
are redirected too, to loopback, and:

- If an upstream is on a redirected port (the default), the daemon's user is
  exempt for that port so obrien can reach it. This exempts all that
  user's processes, so test as another user; `firewall-on` says when it
  applies.
- A loopback-only listener is accepted, with only the local redirect.
- A listener on one specific non-loopback address is refused.

Debugging: `firewall-status` counts redirected connections;
`proxy_connections_total` counts connections obrien accepted. Kernel count
rising but not obrien's: the redirect doesn't reach the listener. Neither:
traffic doesn't match (other port, or connection opened before the rules).

An unreachable upstream gives `502`. To an `https` upstream, obrien uses the
client's SNI (else `Host`) as server name and verifies against it; clients
using an IP, or a name the certificate doesn't cover, get `502`. To skip
re-encryption on a trusted hop, set `--upstream-https http://127.0.0.1:80`:
requests go in cleartext with `X-Forwarded-Proto: https`. The upstream must
not redirect them to HTTPS, or they loop.

## License

Copyright (C) 2026 Bjarni R. Einarsson

This code is licensed AGPL-3.0-or-later; see [`LICENSE`](LICENSE). Thanks!
