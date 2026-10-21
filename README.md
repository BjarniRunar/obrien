# police

`police` is a security tool: a reverse HTTP proxy that sits in front of an
upstream service so it can **monitor and filter** the requests sent to it.

It is **not** a load balancer. It forwards traffic to a single upstream, and
it exists to see and control that traffic, not to spread it across servers.

## Features

- Listens for cleartext HTTP, terminates TLS (HTTP/1.1 and HTTP/2), or both at once.
- Forwards allowed requests to the upstream service (one address per
  listener), re-encrypting TLS traffic, keeping the client's `Host`
  header and setting `X-Forwarded-For`, `-Host` and `-Proto`.
- Every request passes through monitoring hooks: metrics, and a bounded
  in-memory log of recent requests (`police requests`).

- Every request header must pass a strict sanity check (well-formed request
  line and fields, no ambiguous framing headers) or is rejected.
- Requests whose raw header matches any of a list of named regular
  expressions are rejected. The list lives in memory and is edited with
  `police rules-add`, `rules-rm` and `rules-list`.

## Layout

- `main.go`, `police.go`: the daemon. Settings, listeners, TLS, metrics, and
  wiring the pieces below together.
- `firewall.go`: the `firewall-*` RPC methods, which redirect ports 80 and
  443 to the daemon's listeners with nftables.
- [`proxy/`](proxy/README.md): forwarding requests to the upstream.
- `requests.go`: the `requests` RPC method, which shows the request log.
- `rules_api.go`: the `rules-*` RPC methods, which edit the header patterns.
- [`monitor/`](monitor/README.md): observing requests through hooks, and the
  bounded in-memory request log.
- [`rules/`](rules/README.md): inspecting and filtering requests.
- [`ARCH-DECISIONS.md`](ARCH-DECISIONS.md): high-level design decisions.

## Build

The daemon scaffolding (start/stop, config, metrics, logging, the CLI) comes
from [kettlingar-go](https://github.com/mailpile/kettlingar-go), checked out as
a git submodule in `submodules/kettlingar-go`. A `replace` directive in `go.mod`
points the build at that checkout, so local changes to kettlingar take effect
on the next build.

```sh
git submodule update --init   # fresh clone only
make                          # builds ./police
```

The binary is statically linked (cgo is disabled), so it can be copied to
other Linux machines of the same architecture, however old their libc.
Cross-compile with e.g. `make GOARCH=arm64`.

Requires Go 1.25.7+ (fetched automatically when `GOTOOLCHAIN=auto`).

## Usage

```sh
./police start                                   # cleartext on :8000 -> 127.0.0.1:80
./police start --upstream http://10.0.0.5:80 --http :80 \
               --https :443 --cert cert.pem --key key.pem
./police metrics                                 # OpenMetrics: proxy_*, rules_*, monitor_*
./police requests --count 20                     # most recent proxied requests
./police rules-list                              # header patterns, see below
./police stop
```

`start` runs the daemon in the background and returns once its listeners are
bound; a bad address or certificate makes it fail with a non-zero exit code.
Add `--foreground` (`-F`) to keep it attached. Run `./police --help` while the
daemon is up to see every command it offers.

| Setting      | Default                 | Description                          |
|--------------|-------------------------|--------------------------------------|
| `--upstream` | `http://127.0.0.1:80`   | Where the cleartext listener forwards |
| `--upstream-https` | `https://127.0.0.1:443` | Where the TLS listener forwards; an `http://` URL forwards cleartext |
| `--http`     | `:8000`                 | Cleartext listen address, or `off`   |
| `--https`    | `off`                   | TLS listen address, or `off`         |
| `--cert`     | `off`                   | TLS certificate (PEM)                |
| `--key`      | `off`                   | TLS private key (PEM)                |
| `--request-log` | `1000`               | Recent requests kept in memory, or `0` to disable |

Each setting can also come from a `POLICE_<NAME>` environment variable (for
example `POLICE_UPSTREAM`), or from `police.yaml` in the user config directory
(`~/.config/kettlingar/` on Linux).

### Filtering requests

Every request's header is checked before it is proxied. A header that does
not parse strictly, or has ambiguous framing (e.g. duplicate
`Content-Length`, or both `Content-Length` and `Transfer-Encoding`), is
rejected with 403 and counted in `rules_invalid_total`.

Then the raw header, exactly as sent (request line, fields, CRLFs), is
matched against named regular expressions ([Go syntax](https://pkg.go.dev/regexp/syntax));
any match rejects the request, and `rules_matched_total{rule="NAME"}`
counts how often each one matched; `rules-list` shows the same count. It
is kept by name, so it carries over when a rule is replaced or re-added
under the same name, and resets when the daemon restarts. HTTP/2 headers have no raw form, so they
are matched as HTTP/1-style text rebuilt from the request, with fields
sorted by name.

```sh
./police rules-add multipart '(?im)^content-type:\s*multipart/'
./police rules-add --replace multipart multipart '(?im)^content-type:\s*multipart/form-data'
./police rules-rm multipart
./police rules-list                              # each rule with its match count
./police rules-list -f json > rules.json         # save
./police rules-add --file "$PWD/rules.json"      # load (path read by the daemon)
```

Use `(?i)` for case-insensitive matching and `(?m)` to make `^` and `$` match
at each line; lines end in `\r\n`, so `$` alone sees the `\r`. The patterns
live only in the daemon's memory and are lost when it stops. `rules-add
--file` must be given an absolute path, since the daemon reads it.

### Sitting in front of a web server on ports 80 and 443

The defaults are for running police in front of a web server (e.g. caddy)
that stays on this host's ports 80 and 443. police listens on unprivileged
ports and forwards to `127.0.0.1:80` and `127.0.0.1:443`. The daemon then has
the kernel firewall redirect incoming connections for 80/443 to police:

```sh
./police start --http :8000 --https :8443 --cert cert.pem --key key.pem
                          # forwards to 127.0.0.1:80 and https://127.0.0.1:443
./police firewall-on     # 80 -> 8000, 443 -> 8443
./police firewall-on --local true   # also redirect connections made on this host
./police firewall-status    # show the installed rules and the kernel's counters
./police firewall-off
```

The daemon redirects to the ports its listeners actually bound, and only for
listeners that are running, so the daemon must be up. It runs `sudo -n nft`,
so its user needs passwordless sudo for `nft`. All rules live in a dedicated
nftables table, `inet police`, so `firewall-on` replaces earlier police
rules and `firewall-off` touches nothing else. The rules stay in place
when the daemon stops.

Only connections addressed to this host itself are redirected. Traffic routed
through it, such as containers or VMs connecting out to port 80/443, is left
alone. By default only traffic arriving from other hosts is redirected, and a
loopback-only listener (e.g. `127.0.0.1:8000`) is refused because it cannot
receive that traffic. With `--local true`, connections made on the police
host to its own addresses are redirected too, to loopback. In that mode:

- If either listener's upstream is on a redirected port (the default),
  connections from the daemon's own user to that port are exempt, so police
  can reach the web server without looping back into itself. This exempts
  every process running as that user, so test from a different user;
  `firewall-on` says when it applies.
- A loopback-only listener is accepted and gets only the local redirect.
- A listener bound to one specific non-loopback address is refused, since
  loopback traffic cannot reach it.

To check that redirected traffic arrives, compare the kernel's view with
police's own: `firewall-status` shows how many connections each rule
redirected (NAT counters count each connection once), and the
`proxy_connections_total` metric counts connections police accepted, before
any TLS handshake or request. If the kernel count grows and police's does
not, the redirect is not reaching the listener. If neither grows, the
traffic is not matching the rules, for example because it uses another port
or the connection was opened before the rules were installed.

If the upstream can't be reached, clients get `502 Bad Gateway`.

When the TLS listener forwards to an `https` upstream, police opens a new TLS
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
