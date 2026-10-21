// Package rules inspects requests before they are proxied, and decides
// whether they may pass. Requests are judged on their raw header, which
// Listen captures from the connection.
package rules

import (
	"net/http"
	"time"
)

// Rule inspects a request. Returning a non-nil error rejects it; the error
// text is used for logging, never sent to the client.
type Rule interface {
	Check(r *http.Request) error
}

// RejectFunc is called for each rejected request, e.g. to log or count it.
type RejectFunc func(r *http.Request, err error)

// TimeFunc is called once per request with the time spent running rules,
// e.g. to count and time rule checks.
type TimeFunc func(r *http.Request, d time.Duration)

// Filter attaches each request's header (see HeaderFrom) and runs every rule
// against it, in order. The first rule to reject a request ends it with 403
// Forbidden; otherwise next handles it.
//
// Every request must pass through Filter, even with no rules, because it
// also consumes the header Listen captured for it and restores Request.TLS.
func Filter(rules []Rule, onReject RejectFunc, onTime TimeFunc, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h, tlsState := takeHeader(r)
		r = r.WithContext(withHeader(r.Context(), h))
		if r.TLS == nil {
			r.TLS = tlsState
		}
		for _, rule := range rules {
			if err := rule.Check(r); err != nil {
				if onTime != nil {
					onTime(r, time.Since(start))
				}
				if onReject != nil {
					onReject(r, err)
				}
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		if onTime != nil {
			onTime(r, time.Since(start))
		}
		next.ServeHTTP(w, r)
	})
}
