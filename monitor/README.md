# monitor/

Observing proxied traffic. Every request passes through `Middleware`, which
summarises it once the response is written and hands the summary to hooks.
Deciding whether a request may pass lives in [`../rules`](../rules/README.md).

- `monitor.go`: `Record` (time, listener, client address, method, host, URI,
  protocol, status, duration), the `Hook` interface and `HookFunc` adapter,
  and `Middleware`. Hooks run synchronously on the request's goroutine, in
  order, so they must be fast and safe for concurrent use. Middleware wraps
  the rules filter, so rejected requests are observed too, with the
  `--blocked-status` status.
  A `TimeFunc` callback gets the time the hooks took for each request.
  An optional `Annotator` runs before each request, may replace it (e.g.
  with a new context or body), and can add to the `Record` after the
  response, before the hooks run; its time counts as hook time. The
  daemon uses it to fill `Record.Trace` (see [`../trace`](../trace/README.md))
  when the request log or trace log is on, for requests answered with 2xx or 3xx.
- `log.go`: `Log`, a hook keeping the newest N records in a fixed-size ring
  buffer; `Recent(n)` returns them oldest first.
- `log_test.go`: tests for `Log`.
- `tracelog.go`: `TraceLog`, a hook writing each record to a file as a
  Common Log Format line (no byte count) followed by the host and the
  trace, or `NOTRACE` for untraced requests so they can be filtered out.
- `tracelog_test.go`: tests for the `TraceLog` line format.

Connections are counted separately, by the daemon, as
`proxy_connections_total`: a connection that never completes a request
produces no Record.

The daemon installs two hooks: its metrics (`proxy_requests_total`,
`proxy_request_time_us`) and, unless `--request-log 0`, a `Log` that the
`obrien requests` command reads, and, with `--trace-log PATH`, a
`TraceLog` appending to that file. The hooks' own cost is recorded as
`monitor_hooks_total` and `monitor_hook_time_us`, by listener.
