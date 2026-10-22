# proxy/

Moves traffic to the upstream; never decides whether it may pass (that is
[`../rules`](../rules/README.md)).

- `proxy.go`: `New` builds the reverse proxy: pooled upstream connections,
  immediate flushing, `Host` kept, `X-Forwarded-*` set (a client's own
  `X-Forwarded-For` kept only from trusted proxies, parsed by
  `ParseTrusted`), 502 and an `ErrorFunc` call on upstream failure. Always
  dials the target address; for `https` targets, TLS uses the client's SNI
  or `Host` as server name and verifies against it. `NewServer` builds an
  `http.Server` with timeouts for untrusted clients.
- `proxy_test.go`: trusted `X-Forwarded-For` tests.
- `bufpool.go`: pooled 32 KB copy buffers.
- `statuswriter.go`: `StatusWriter` records the status without hiding
  `Flush`.

Listeners are set up in `../obrien.go`; TLS is terminated by
`rules.Listen`.
