# rules/

Logic for processing traffic: inspecting each request before it is proxied
and deciding whether it may pass. Forwarding itself lives in
[`../proxy`](../proxy/README.md).

- `rules.go`: the `Rule` interface (`Check(*http.Request) error`, where an
  error means reject) and `Filter`, the middleware that attaches each
  request's `Header`, runs rules in order and answers the first rejection
  with the status given to `Filter` and a small HTML page linking to the URL of the
  rule's `Rejection` error, or to Filter's default URL. The rejection
  reason goes to a `RejectFunc` callback (logged and counted by the
  daemon); it is never sent to the client. A
  `TimeFunc` callback gets the time each request spent in the rules.
- `capture.go`: `Listen` wraps a listener so the raw bytes of every HTTP/1.x
  request header are captured, and with a TLS config also terminates TLS.
  The capture follows the stream's framing (Content-Length, chunked bodies)
  itself, and `Filter` checks each captured header against the request
  net/http parsed, so the two parsers cannot disagree about where a request
  starts. `ConnContext` must be set on the `http.Server`. HTTP/2
  connections are not captured: their header is rebuilt from the decoded
  request instead. After a request with `Upgrade` (or `CONNECT`) capture
  stops, so if the upgrade is refused the connection's later requests are
  rejected.
- `header.go`: `Header` (raw bytes, request line, fields in wire order, parse
  error), `HeaderSlot` (`WithHeaderSlot`), through which `Filter` hands the
  header it judged to code wrapping it, `ParseHeader` (the parser, for
  tests elsewhere), the strict HTTP/1.x parser, and `checkHeader`, the sanity rules:
  CRLF line endings, no line folding, valid method, target, protocol, field
  names and values; at most one `Content-Length`, `Transfer-Encoding`,
  `Content-Type` and `Host`, each of which must parse; no `Content-Length`
  together with `Transfer-Encoding`, which may only be `chunked`.
- `patterns.go`: `Sanity`, the rule rejecting any request whose header failed
  to parse, broke the sanity rules or was not captured (`SanityError`); and
  `Patterns`, an editable, named list of regular expressions matched
  against the raw header, each with an optional explanation `URL` (checked
  by `ValidURL`: http(s) or an absolute path). Every pattern is tried and
  each match reported to a `MatchFunc`. A rejection carries the URL of the
  first matching pattern that has one. `Add` refuses names already in use
  (unless replacing one); `Update` replaces same-named patterns in place
  and appends the rest. Edits are atomic and safe while traffic flows.
- `crs.go`: `CRS`, a rule running the OWASP Core Rule Set with
  [Coraza](../submodules/coraza), built from the local submodule. Unlike
  the other rules it judges the request as net/http parsed it, including
  up to `BodyLimit` (default 1 MiB) of the body, which it reads and puts
  back in `Request.Body`.
  In block mode an interruption, or a failure to read the body, is a
  `Rejection` wrapping a `CRSError`; in detect mode an interruption goes to
  an `OnDetect` callback and the request passes. Logged CRS rules that
  matched are reported to a `MatchFunc` as `crs-<id>`, and the time each
  check took to a `TimeFunc`. Errors go to a `CRSErrorFunc` with a type
  (the `CRSErr*` constants): failures reading the body or in Coraza, a
  body inspected only in part because it was over the limit (which does
  not reject it), and the malformed-request rules in `crs.conf`.
- `crs.conf`: the engine settings `CRS` loads before the CRS setup (based on
  Coraza's `coraza.conf-recommended`): body limits, body processors, and no
  response inspection or audit log.
- `crs_test.go`: tests for `CRS` (attacks in query and body, clean
  requests, the body passed on intact, detect mode, error types).
- `rules_test.go`: tests for the parser, the patterns, the block page, and capture over real
  connections (pipelining, chunked bodies, TLS with HTTP/1.1 and HTTP/2).

The daemon runs `Sanity` then its `Patterns`, edited by the `rules-list`,
`rules-add` and `rules-rm` commands, then `CRS` if `--crs` is on. It counts
rejections (`rules_rejected_total`), sanity failures
(`rules_invalid_total`), pattern and CRS rule matches
(`rules_matched_total`, by rule), CRS rejections
(`rules_crs_rejected_total`), CRS errors by type
(`rules_crs_errors_total{type=…}`), the time spent in the CRS
(`rules_crs_check_time_us`) and, in detect mode, requests the CRS would
have rejected (`rules_detected_total`).
