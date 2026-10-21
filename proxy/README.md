# proxy/

Everything needed to move HTTP traffic from clients to the upstream, and
nothing that decides *whether* it should. Traffic inspection and filtering
live in [`../rules`](../rules/README.md).

- `proxy.go`: `New` builds the reverse proxy (pooled upstream connections,
  immediate flushing for streaming, `Host` preserved, `X-Forwarded-*` set,
  502 plus an `ErrorFunc` callback when the upstream fails). It always dials
  the target address; for an `https` target the TLS connection uses the
  client's SNI or `Host` as the server name and verifies the upstream's
  certificate against it. `NewServer`
  builds an `http.Server` with timeouts for untrusted clients.
- `bufpool.go`: reuses 32 KB copy buffers to cut allocations.
- `statuswriter.go`: `StatusWriter` records the response status for
  monitoring, without hiding `Flush` from the proxy.

Listener setup is done by the daemon in `../obrien.go`, and TLS is
terminated by `rules.Listen`, which captures raw headers for inspection; the
servers built here are handed those listeners.
