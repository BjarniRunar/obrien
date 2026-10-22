# obrien

`obrien` is a security tool: a reverse HTTP proxy that sits in front of an
upstream service so it can **monitor and filter** the requests sent to it.

It is **not** a load balancer. It forwards traffic to a single upstream, and
it exists to see and control that traffic, not to spread it across servers.

## Features

- Listens for cleartext HTTP, terminates TLS (HTTP/1.1 and HTTP/2), or both at once.
- Forwards allowed requests to the upstream service (one address per
  listener), re-encrypting TLS traffic, keeping the client's `Host`
  header and setting `X-Forwarded-For`, `-Host` and `-Proto`.
- Every request passes through monitoring hooks: metrics, and a bounded
  in-memory log of recent requests (`obrien requests`). Requests answered
  with 2xx or 3xx also get a trace of their shape (path, query, selected
  headers, body structure) without their content. With `--trace-log`, every
  request is also appended to a file as an access-log line ending in its
  trace, or `NOTRACE`.

- Every request header must pass a strict sanity check (well-formed request
  line and fields, no ambiguous framing headers) or is rejected.
- Requests whose raw header matches any of a list of named regular
  expressions are rejected. The list lives in memory and is edited with
  `obrien rules-add`, `rules-rm` and `rules-list`.
- Optionally, requests (including up to 1 MiB of their body) are checked
  against the [OWASP Core Rule Set](https://coreruleset.org/) using
  [Coraza](https://coraza.io/), either blocking or only logging what would
  be blocked (`--crs block` or `--crs detect`).

## Layout

- `main.go`, `obrien.go`: the daemon. Settings, listeners, TLS, metrics, and
  wiring the pieces below together.
- `firewall.go`: the `firewall-*` RPC methods, which redirect ports 80 and
  443 to the daemon's listeners with nftables.
- [`proxy/`](proxy/README.md): forwarding requests to the upstream.
- `requests.go`: the `requests` RPC method, which shows the request log.
- `annotator_test.go`: tests that only requests answered with 2xx or 3xx
  get a trace in the request log.
- `rules_api.go`: the `rules-*` RPC methods, which edit the header patterns.
- [`monitor/`](monitor/README.md): observing requests through hooks, and the
  bounded in-memory request log.
- [`rules/`](rules/README.md): inspecting and filtering requests.
- [`trace/`](trace/README.md): request traces, the shape of each request
  without its content, shown in the request log.
- [`ARCH-DECISIONS.md`](ARCH-DECISIONS.md): high-level design decisions.

## Build

The daemon scaffolding (start/stop, config, metrics, logging, the CLI) comes
from [kettlingar-go](https://github.com/mailpile/kettlingar-go), checked out as
a git submodule in `submodules/kettlingar-go`. A `replace` directive in `go.mod`
points the build at that checkout, so local changes to kettlingar take effect
on the next build. [Coraza](https://github.com/corazawaf/coraza) is checked
out and built the same way, from `submodules/coraza`; the OWASP Core Rule Set
it runs comes embedded in the `coraza-coreruleset` Go module.

```sh
git submodule update --init   # fresh clone only
make                          # builds obrien
```

The binary is statically linked (cgo is disabled), so it can be copied to
other Linux machines of the same architecture, however old their libc.
Cross-compile with e.g. `make GOARCH=arm64`.

Pushing a tag starting with `v` (e.g. `v0.1.0`) makes GitHub Actions
(`.github/workflows/release.yml`) run the tests and publish a release with
linux amd64 and arm64 binaries and their SHA-256 sums.

Requires Go 1.26+ (fetched automatically when `GOTOOLCHAIN=auto`).

## Usage

```sh
obrien start                 # cleartext on :9080 -> 127.0.0.1:80

# Handle both HTTP (:9080) and HTTPS (:9443) traffic
obrien start --cert cert.pem --key key.pem

obrien firewall-on           # Intercept traffic using nft
obrien metrics               # OpenMetrics: proxy_*, rules_*, monitor_*
obrien requests --count 20   # most recent proxied requests
obrien rules-list            # header patterns, see below
obrien firewall-off          # Remove nft rules
obrien stop
```

`start` runs the daemon in the background and returns once its listeners are
bound; a bad address or certificate makes it fail with a non-zero exit code.
Add `--foreground` (`-F`) to keep it attached. Run `obrien --help` while the
daemon is up to see every command it offers.

| Setting      | Default                 | Description                          |
|--------------|-------------------------|--------------------------------------|
| `--upstream` | `http://127.0.0.1:80`   | Where the cleartext listener forwards |
| `--upstream-https` | `https://127.0.0.1:443` | Where the TLS listener forwards; an `http://` URL forwards cleartext |
| `--http`     | `:9080`                 | Cleartext listen address, or `off`   |
| `--https`    | `:9443`                 | TLS listen address, or `off`; only used when `--cert` and `--key` are set |
| `--cert`     | `off`                   | TLS certificate (PEM)                |
| `--key`      | `off`                   | TLS private key (PEM)                |
| `--request-log` | `1000`               | Recent requests kept in memory, or `0` to disable |
| `--trace-log`   | `off`                | Absolute path of a file to append an access-log line with the trace to, per request |
| `--crs`      | `off`                   | OWASP Core Rule Set: `block`, `detect` (log only) or `off` |
| `--crs-paranoia` | `1`                 | CRS paranoia level, 1-4 |
| `--crs-conf` | `off`                   | Absolute path of extra CRS directives (tuning, exclusions) |
| `--trusted-proxies` | `off`            | Comma-separated IPs/CIDRs whose `X-Forwarded-For` is kept and appended to |
| `--blocked-status` | `502`             | HTTP status for blocked requests (400-599) |
| `--blocked-url` | `off`                | Page linked from block responses to explain the block, unless the rule sets its own |

Each setting can also come from a `OBRIEN_<NAME>` environment variable (for
example `OBRIEN_UPSTREAM`), or from `obrien.yaml` in the user config directory
(`~/.config/kettlingar/` on Linux).

### Filtering requests

Every request's header is checked before it is proxied. A header that does
not parse strictly, or has ambiguous framing (e.g. duplicate
`Content-Length`, or both `Content-Length` and `Transfer-Encoding`), is
rejected and counted in `rules_invalid_total`.

Then the raw header, exactly as sent (request line, fields, CRLFs), is
matched against named regular expressions ([Go syntax](https://pkg.go.dev/regexp/syntax));
any match rejects the request, and `rules_matched_total{rule="NAME"}`
counts how often each one matched; `rules-list` shows the same count. It
is kept by name, so it carries over when a rule is replaced or re-added
under the same name, and resets when the daemon restarts. HTTP/2 headers have no raw form, so they
are matched as HTTP/1-style text rebuilt from the request, with fields
sorted by name.

```sh
obrien rules-add multipart '(?im)^content-type:\s*multipart/'
obrien rules-add \
     --replace multipart \
     multipart '(?im)^content-type:\s*multipart/form-data'
obrien rules-add \
     --url https://example.com/blocked.html \
     upload '(?im)^content-type:\s*multipart/'
obrien rules-rm multipart
obrien rules-list                          # each rule with its match count
obrien rules-list -f json > rules.json     # save to file
obrien rules-add --file "$PWD/rules.json"  # add/update rules from file
```

Use `(?i)` for case-insensitive matching and `(?m)` to make `^` and `$` match
at each line; lines end in `\r\n`, so `$` alone sees the `\r`. The patterns
live only in the daemon's memory and are lost when it stops. `rules-add
--file` must be given an absolute path, since the daemon reads it.

A blocked request gets `--blocked-status` (default `502 Bad Gateway`) with a
short HTML page linking to a page explaining why: the URL of the first matching
rule that has one (`rules-add --url`), or else `--blocked-url`. With neither,
the page has no link. URLs must be `http(s)://` or an absolute path on the same
site.

### Sitting in front of a web server on ports 80 and 443

The defaults are for running obrien in front of a web server (e.g. caddy)
that stays on this host's ports 80 and 443. obrien listens on unprivileged
ports and forwards to `127.0.0.1:80` and `127.0.0.1:443`. The daemon then has
the kernel firewall redirect incoming connections for 80/443 to obrien:

```sh
# Listen on 9080/9443, forward to 127.0.0.1:80 and https://127.0.0.1:443
obrien start --cert cert.pem --key key.pem

obrien firewall-on               # 80 -> 9080, 443 -> 9443
obrien firewall-on --local true  # also redirect localhost connections
obrien firewall-status           # show active rules and kernel's counters
obrien firewall-off
```

The daemon redirects to the ports its listeners actually bound, and only for
listeners that are running, so the daemon must be up. It runs `sudo -n nft`,
so its user needs passwordless sudo for `nft`. All rules live in a dedicated
nftables table, `inet obrien`, so `firewall-on` replaces earlier obrien
rules and `firewall-off` touches nothing else. The rules stay in place
when the daemon stops.

Only connections addressed to this host itself are redirected. Traffic routed
through it, such as containers or VMs connecting out to port 80/443, is left
alone. By default only traffic arriving from other hosts is redirected, and a
loopback-only listener (e.g. `127.0.0.1:9080`) is refused because it cannot
receive that traffic. With `--local true`, connections made on the obrien
host to its own addresses are redirected too, to loopback. In that mode:

- If either listener's upstream is on a redirected port (the default),
  connections from the daemon's own user to that port are exempt, so obrien
  can reach the web server without looping back into itself. This exempts
  every process running as that user, so test from a different user;
  `firewall-on` says when it applies.
- A loopback-only listener is accepted and gets only the local redirect.
- A listener bound to one specific non-loopback address is refused, since
  loopback traffic cannot reach it.

To check that redirected traffic arrives, compare the kernel's view with
obrien's own: `firewall-status` shows how many connections each rule
redirected (NAT counters count each connection once), and the
`proxy_connections_total` metric counts connections obrien accepted, before
any TLS handshake or request. If the kernel count grows and obrien's does
not, the redirect is not reaching the listener. If neither grows, the
traffic is not matching the rules, for example because it uses another port
or the connection was opened before the rules were installed.

If the upstream can't be reached, clients get `502 Bad Gateway`.

When the TLS listener forwards to an `https` upstream, obrien opens a new TLS
connection using the name the client asked for (its SNI, else its `Host`) and
verifies the upstream's certificate against that name, not against the
upstream's address. A client that connects by IP address, or asks for a name
the upstream's certificate doesn't cover, gets `502`.

Re-encrypting costs a second TLS handshake and encryption on every
connection. To save that CPU when the hop to the upstream is trusted, give
`--upstream-https` an `http://` URL, e.g. `--upstream-https
http://127.0.0.1:80`. Requests from the TLS listener are then forwarded in
cleartext, with `X-Forwarded-Proto: https` so the upstream knows the client
used TLS. The upstream must not redirect those requests to HTTPS, or they
loop.

## License

Copyright (C) 2026 Bjarni R. Einarsson

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU Affero General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your
option) any later version. See [`LICENSE`](LICENSE) for the full text; each
Go source file carries an `SPDX-License-Identifier: AGPL-3.0-or-later` line.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.
