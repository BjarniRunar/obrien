# obrien

Obrien is a drop-in "web application firewall"; a reverse HTTP proxy that
monitors and optionally blocks requests to a single upstream web server. 

## Features

- No modifications to the web server (or its configuration) is required
- Enabled/disabled by adding or removing Linux kernel firewalling rules
- Can handle both incoming HTTP and HTTPS fraffic
- Can forward requests to a HTTP and/or HTTPS upstreams
- Sets (after stripping) `X-Forwarded-For`/`-Host`/`-Proto` headers
- Optionally tunnels PageKite and `CONNECT` unmodified, to front a PageKite relay
- Ensures any HTTP requests is well formed before it reaches your upstream
- Optional enforcement of [OWASP CRS](https://coreruleset.org/) rules
- Optional custom rules (header regexps) can be added/removed at runtime
- Learning mode builds a profile of normal traffic to one or more websites
- Enforcing mode blocks any traffic not fitting the profile
- Exposes (Prometheus compatible) OpenMetrics

## Build

Prerequisites: `golang` and `make`

```sh
git clone https://github.com/BjarniRunar/obrien
cd obrien
make
```

## Pre-built binaries

See: <https://github.com/BjarniRunar/obrien/releases>

Download the binary for your platform, install and make executable:

```sh
wget https://github.com/BjarniRunar/obrien/.../obrien-v0.0.1-linux-amd64
sudo install -m 0755 obrien-v*amd64 /usr/local/bin/obrien
```

## Usage

```sh
obrien start                 # cleartext on :9080 -> 127.0.0.1:80
obrien start --cert cert.pem --key key.pem   # also HTTPS on :9443
obrien firewall-on | sudo sh # redirect 80/443
obrien metrics               # OpenMetrics: proxy_*, rules_*, monitor_*
obrien requests --count 20   # recent requests
obrien rules-list
obrien firewall-off | sudo sh
obrien stop
```

`start` returns once listeners are bound, failing on a bad address or
certificate; `--foreground` (`-F`) stays attached. `obrien --help` with the
daemon up lists every command.

| Setting            | Default                | Description                                 |
|--------------------|------------------------|---------------------------------------------|
| `--upstream`       | `http://127.0.0.1:80`  | Cleartext listener's upstream               |
| `--upstream-https` | `https://127.0.0.1:443`| HTTPS upstream; use `http://` for cleartext |
| `--http`           | `:9080`                | Cleartext listening address:port, or `off`  |
| `--https`          | `:9443`                | TLS listening address, or `off`             |
| `--cert`           | `off`                  | Path to TLS certificate (PEM)               |
| `--key`            | `off`                  | Path to TLS private key (PEM)               |
| `--tls-keys`       | `off`                  | Combined PEM files/dirs, chosen by SNI      |
| `--allow-pagekite` | `false`                | Front a PageKite relay (see below)          |
| `--request-log`    | `1000`                 | Requests log lines kept in memory; `0`=off  |
| `--trace-log`      | `off`                  | Path to the trace log file (auto-rotates)   |
| `--crs`            | `off`                  | OWASP CRS: `block`, `detect` or `off`       |
| `--crs-paranoia`   | `1`                    | CRS paranoia level, 1-4                     |
| `--crs-conf`       | `off`                  | Absolute path of extra CRS directives       |
| `--trusted-proxies`| `off`                  | IPs/CIDRs we `X-Forwarded-For` from         |
| `--blocked-status` | `502`                  | Status for blocked requests (400-599)       |
| `--blocked-url`    | `off`                  | Default explanation page linked from blocks |

Settings can also come from `OBRIEN_<NAME>` variables
(e.g. `OBRIEN_UPSTREAM`)
or `obrien.yaml` in the user config directory (`~/.config/obrien/`).
The command-line overrides both the config file and the environment.


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
obrien firewall-on               # print: 80 -> 9080, 443 -> 9443
obrien firewall-on --local true  # print: also redirect local connections
obrien firewall-on | sudo sh     # apply
obrien firewall-status | sudo sh # rules and kernel counters
obrien firewall-off | sudo sh
obrien firewall-on --mode iptables   # force nft or iptables (default auto)
```

Redirects target the ports actually bound by running listeners, so the
daemon must be up. The `firewall-*` commands only print a shell script, for
the operator to review and run as root. It uses `/usr/sbin/nft` if present,
with rules in table `inet obrien` only; else `iptables` (and `ip6tables`
if found), with rules in nat chains `OBRIEN-PRE`/`OBRIEN-OUT` only. Rules
survive daemon stop.

Only connections addressed to this host are redirected, not routed traffic
(containers, VMs). By default only traffic from other hosts is; a
loopback-only listener is refused. With `--local true`, local connections
are redirected too, to loopback, and:

- If an upstream is on a redirected port (the default), the daemon's user is
  exempt for that port so obrien can reach it. This exempts all that
  user's processes, so test as another user; `firewall-on` notes when it
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

### Multiple certificates

`--tls-keys` takes PEM files holding a certificate chain (leaf first) and
its key, or directories of them; every file in a directory is tried, and
non-PEM files are skipped. The certificate is chosen by SNI: exact name,
then wildcard, then the default (`--cert`/`--key`, else the first loaded).
Files and directories are rechecked at most once a minute; a file that
fails to load keeps its previous certificate and is logged.

```sh
obrien start --tls-keys /etc/pagekite/keys,/srv/site.pem
```

### In front of a PageKite relay

`obrien start --allow-pagekite true`:

- passes connections opening with `CONNECT`, `PING` or a PageKite
  WebSocket tunnel request straight to the upstream, unmodified and
  bypassing all rules (`proxy_tunnels_total`);
- passes TLS for names no certificate covers to `--upstream-https`'s
  address still encrypted, uninspected (`proxy_tls_passthrough_total`);
- gives each client connection its own upstream connections, as the relay
  routes each by its first request, and serves HTTP/1.1 only.

Other traffic is inspected as usual. Tunnels and passthrough are logged,
but don't appear in `requests` or the trace log.

## Development

This software is written using the assistance of an LLM coding tool,
but humans are always responsible for the outcomes and are expected to review code before committing it.
If you cannot explain what a pull request does, how, and why,
(without consulting with the LLM)
then the pull request is not ready for submission.

The file [DEV-RULES.md](DEV-RULES.md) contains the basic rules,
we expect both humans and LLMs to adhere to when contributing to this project.

The file [ARCH-DECISIONS.md](ARCH-DECISIONS.md)
summarizes the hows and whys of what the software does.


## License

Copyright (C) 2026 Bjarni R. Einarsson

This code is licensed AGPL-3.0-or-later; see [`LICENSE`](LICENSE). Thanks!
