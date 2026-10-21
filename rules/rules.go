// Package rules inspects requests before they are proxied, and decides
// whether they may pass. No rules are implemented yet.
package rules

import "net/http"

// Rule inspects a request. Returning a non-nil error rejects it; the error
// text is used for logging, never sent to the client.
type Rule interface {
	Check(r *http.Request) error
}

// RejectFunc is called for each rejected request, e.g. to log or count it.
type RejectFunc func(r *http.Request, err error)

// Filter runs every rule against each request, in order. The first rule to
// reject a request ends it with 403 Forbidden; otherwise next handles it.
func Filter(rules []Rule, onReject RejectFunc, next http.Handler) http.Handler {
	if len(rules) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, rule := range rules {
			if err := rule.Check(r); err != nil {
				if onReject != nil {
					onReject(r, err)
				}
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
