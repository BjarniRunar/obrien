# rules/

Inspects each request before it is proxied and decides whether it passes.
Forwarding is in [`../proxy`](../proxy/README.md).

- `rules.go`: `Rule` (`Check(*http.Request) error`; an error rejects) and
  `Filter`, the middleware that attaches the request's `Header`, runs rules
  in order, and answers the first rejection with Filter's status and a
  short HTML page linking to the `Rejection`'s URL or Filter's default.
  The reason goes to a `RejectFunc` (logged and counted), never to the
  client. A `TimeFunc` gets each request's time in the rules.
- `capture.go`: `Listen` wraps a listener to capture each HTTP/1.x
  request's raw header, and terminates TLS if given a config. It follows
  the framing (Content-Length, chunked) itself; `Filter` checks each
  capture against net/http's request, so the two parsers can't disagree on
  where a request starts. Requires `ConnContext` on the `http.Server`.
  HTTP/2 isn't captured; its header is rebuilt from the request. Capture
  stops after `Upgrade` or `CONNECT`, so a refused upgrade gets later
  requests on that connection rejected.
- `header.go`: `Header` (raw bytes, request line, fields in wire order,
  parse error); `HeaderSlot` (`WithHeaderSlot`), handing the judged header
  and whether Filter blocked the request, and if for being malformed, to
  outer code; `ParseHeader` (for tests elsewhere); the strict parser;
  and `checkHeader`: CRLF only, no folding; valid method, target,
  protocol, names and values; at most one parseable `Content-Length`,
  `Transfer-Encoding`, `Content-Type` and `Host`; not both
  `Content-Length` and `Transfer-Encoding`, which may only be `chunked`.
- `patterns.go`: `Sanity` rejects headers that failed to parse, broke the
  sanity rules or weren't captured (`SanityError`). `Patterns` is an
  editable, named list of regexes matched against the raw header, each with
  an optional `URL` (`ValidURL`: http(s) or absolute path). All patterns
  are tried and matches reported to a `MatchFunc`; a rejection carries the
  first matching pattern's URL. `Add` refuses used names unless replacing;
  `Update` replaces same-named patterns in place and appends the rest.
  Edits are atomic and safe under traffic.
- `crs.go`: `CRS` runs the OWASP Core Rule Set with
  [Coraza](../submodules/coraza). It judges the request as net/http parsed
  it, including up to `BodyLimit` (1 MiB) of body, which it reads and puts
  back. Block mode: an interruption or body read failure is a `Rejection`
  wrapping a `CRSError`. Detect mode: interruptions go to `OnDetect` and
  the request passes. Matched logged rules go to a `MatchFunc` as
  `crs-<id>`, check time to a `TimeFunc`, errors to a `CRSErrorFunc` by
  type (`CRSErr*`): body read, Coraza, over-limit body (not rejected), and
  `crs.conf`'s malformed-request rules.
- `crs.conf`: engine settings loaded before CRS setup (from Coraza's
  `coraza.conf-recommended`): body limits and processors, no response
  inspection or audit log.
- `crs_test.go`: CRS tests (query and body attacks, clean requests, body
  passed intact, detect mode, error types).
- `rules_test.go`: parser, patterns, block page, and capture over real
  connections (pipelining, chunked, TLS with HTTP/1.1 and HTTP/2).

The daemon runs `Sanity`, its `Patterns` (`rules-list`, `rules-add`,
`rules-rm`), then `CRS` if `--crs` is on. Metrics: `rules_rejected_total`,
`rules_invalid_total`, `rules_matched_total` (by rule),
`rules_crs_rejected_total`, `rules_crs_errors_total{type=…}`,
`rules_crs_check_time_us`, and in detect mode `rules_detected_total`.
