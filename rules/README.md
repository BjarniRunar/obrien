# rules/

Logic for processing traffic: inspecting each request before it is proxied
and deciding whether it may pass. Forwarding itself lives in
[`../proxy`](../proxy/README.md).

- `rules.go`: the `Rule` interface (`Check(*http.Request) error`, where an
  error means reject) and `Filter`, the middleware that attaches each
  request's `Header`, runs rules in order and answers the first rejection
  with `403 Forbidden` and a small HTML page linking to the URL of the
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
  error), the strict HTTP/1.x parser, and `checkHeader`, the sanity rules:
  CRLF line endings, no line folding, valid method, target, protocol, field
  names and values; at most one `Content-Length`, `Transfer-Encoding`,
  `Content-Type` and `Host`, each of which must parse; no `Content-Length`
  together with `Transfer-Encoding`, which may only be `chunked`.
- `patterns.go`: `Sanity`, the rule rejecting any request whose header failed
  to parse, broke the sanity rules or was not captured (`SanityError`); and
  `Patterns`, an editable, named list of regular expressions matched
  against the raw header, each with an optional explanation `URL` (checked
  by `ValidURL`: http(s) or an absolute path). Every pattern is tried and each match reported to
  a `MatchFunc`. `Add` refuses names already in use (unless replacing one);
  A rejection carries the URL of the first matching pattern that has one.
  `Update` replaces same-named patterns in place and appends the rest.
  Edits are atomic and safe while traffic flows.
- `rules_test.go`: tests for the parser, the patterns, the 403 page, and capture over real
  connections (pipelining, chunked bodies, TLS with HTTP/1.1 and HTTP/2).

The daemon runs `Sanity` then its `Patterns`, edited by the `rules-list`,
`rules-add` and `rules-rm` commands, and counts rejections
(`rules_rejected_total`), sanity failures (`rules_invalid_total`) and
pattern matches (`rules_matched_total`, by rule).
