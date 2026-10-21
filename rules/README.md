# rules/

Logic for processing traffic: inspecting each request before it is proxied
and deciding whether it may pass. Forwarding itself lives in
[`../proxy`](../proxy/README.md).

- `rules.go`: the `Rule` interface (`Check(*http.Request) error`, where an
  error means reject) and `Filter`, the middleware that runs rules in order
  and answers the first rejection with `403 Forbidden`. The rejection reason
  goes to a `RejectFunc` callback (logged and counted as
  `rules_rejected_total` by the daemon); it is never sent to the client.

No rules are implemented yet, so the daemon currently passes an empty rule
list and `Filter` lets everything through.
