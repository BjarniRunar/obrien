# monitor/

Observes traffic: `Middleware` summarises each request after its response
and passes it to hooks. Filtering is in [`../rules`](../rules/README.md).

- `monitor.go`: `Record` (time, listener, client, method, host, URI,
  protocol, status, duration), `Hook`/`HookFunc`, and `Middleware`. Hooks
  run synchronously, in order, on the request's goroutine: they must be
  fast and concurrency-safe. Middleware wraps the rules filter, so rejected
  requests are seen too, with the `--blocked-status` status. A `TimeFunc`
  gets the hooks' time. An optional `Annotator` may replace the request
  before it runs and add to the `Record` before the hooks (its time counts
  as hook time); the daemon uses it to fill `Record.Trace`
  ([`../trace`](../trace/README.md)) for 2xx/3xx/4xx responses when the request
  log or trace log is on.
- `log.go`: `Log`, a ring buffer of the newest N requests as `TraceLog`
  lines; `Recent(n)` returns them oldest first.
- `tracelog.go`: `TraceLog` appends each record to a file as a Common Log
  Format line (no byte count), host and trace, or `NOTRACE`; `BLOCKED`
  precedes either when `Record.Blocked` (obrien, not the upstream, rejected it),
  followed by `MALFORMED` when `Record.Malformed` (the sanity check did).
- `log_test.go`, `tracelog_test.go`: tests.

The daemon installs hooks for metrics (`proxy_requests_total`,
`proxy_request_time_us`), a `Log` for `obrien requests` (unless
`--request-log 0`) and a `TraceLog` with `--trace-log PATH`. Hook cost:
`monitor_hooks_total`, `monitor_hook_time_us`, by listener. Connections are
counted by the daemon (`proxy_connections_total`), since one that never
completes a request has no Record.
