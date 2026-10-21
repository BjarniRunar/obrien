# police

`police` is a security tool: a reverse HTTP proxy that sits in front of an
upstream service so it can **monitor and filter** the requests sent to it.

It is **not** a load balancer. It forwards traffic to a single upstream, and
it exists to see and control that traffic, not to spread it across servers.

## Features

- Listens for cleartext HTTP, terminates TLS (HTTP/1.1 and HTTP/2), or both at once.
- Forwards allowed requests to one upstream, keeping the client's `Host`
  header and setting `X-Forwarded-For`, `-Host` and `-Proto`.
- Every request passes through a single handler, which is where monitoring
  and filtering go.

Request inspection and filtering rules are not implemented yet; this is the
bare-bones proxy they will be built on.

## Build

```sh
go build -o police .
```

## Usage

```sh
# cleartext only
./police -upstream http://127.0.0.1:8080 -http :80

# cleartext + TLS termination
./police -upstream http://127.0.0.1:8080 -http :80 -https :443 -cert cert.pem -key key.pem

# TLS only
./police -upstream http://127.0.0.1:8080 -http "" -https :443 -cert cert.pem -key key.pem
```

| Flag        | Default                 | Description                               |
|-------------|-------------------------|-------------------------------------------|
| `-upstream` | `http://127.0.0.1:8080` | The service being protected               |
| `-http`     | `:8000`                 | Cleartext listen address (empty disables) |
| `-https`    | *(empty)*               | TLS listen address (empty disables)       |
| `-cert`     | *(empty)*               | TLS certificate (PEM), needed for `-https` |
| `-key`      | *(empty)*               | TLS private key (PEM), needed for `-https` |

If the upstream can't be reached, clients get `502 Bad Gateway`.
SIGINT/SIGTERM shut the proxy down cleanly, waiting up to 15s for requests in flight.
