# monitor/

Observing proxied traffic. Every request passes through `Middleware`, which
summarises it once the response is written and hands the summary to hooks.
Deciding whether a request may pass lives in [`../rules`](../rules/README.md).

- `monitor.go`: `Record` (time, listener, client address, method, host, URI,
  protocol, status, duration), the `Hook` interface and `HookFunc` adapter,
  and `Middleware`. Hooks run synchronously on the request's goroutine, in
  order, so they must be fast and safe for concurrent use. Middleware wraps
  the rules filter, so rejected requests are observed too (status 403).
- `log.go`: `Log`, a hook keeping the newest N records in a fixed-size ring
  buffer; `Recent(n)` returns them oldest first.
- `log_test.go`: tests for `Log`.

Connections are counted separately, by the daemon, as
`proxy_connections_total`: a connection that never completes a request
produces no Record.

The daemon installs two hooks: its metrics (`proxy_requests_total`,
`proxy_request_time_us`) and, unless `--request-log 0`, a `Log` that the
`police requests` command reads.
