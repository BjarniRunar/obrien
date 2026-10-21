// SPDX-License-Identifier: AGPL-3.0-or-later

// Package rules inspects requests before they are proxied, and decides
// whether they may pass. Requests are judged on their raw header, which
// Listen captures from the connection.
package rules

import (
	"errors"
	"html"
	"net/http"
	"time"
)

// Rule inspects a request. Returning a non-nil error rejects it; the error
// text is used for logging, never sent to the client.
type Rule interface {
	Check(r *http.Request) error
}

// Rejection is a rule error naming the page that explains the rejection.
// An empty URL means Filter's default.
type Rejection struct {
	URL string
	Err error
}

func (e Rejection) Error() string { return e.Err.Error() }
func (e Rejection) Unwrap() error { return e.Err }

// RejectFunc is called for each rejected request, e.g. to log or count it.
type RejectFunc func(r *http.Request, err error)

// TimeFunc is called once per request with the time spent running rules,
// e.g. to count and time rule checks.
type TimeFunc func(r *http.Request, d time.Duration)

// Filter attaches each request's header (see HeaderFrom) and runs every rule
// against it, in order. The first rule to reject a request ends it with the
// given status and a short HTML page linking to the rule's Rejection URL, or
// to infoURL if the rule gave none (no link if both are empty); otherwise
// next handles it.
//
// Every request must pass through Filter, even with no rules, because it
// also consumes the header Listen captured for it and restores Request.TLS.
func Filter(rules []Rule, status int, infoURL string, onReject RejectFunc, onTime TimeFunc, next http.Handler) http.Handler {
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
				link := infoURL
				var rej Rejection
				if errors.As(err, &rej) && rej.URL != "" {
					link = rej.URL
				}
				blocked(w, status, link)
				return
			}
		}
		if onTime != nil {
			onTime(r, time.Since(start))
		}
		next.ServeHTTP(w, r)
	})
}

func blocked(w http.ResponseWriter, status int, link string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	body := "<!DOCTYPE html>\n<title>Sorry</title>\n<h1>Sorry</h1>\n<p>This request was blocked."
	if link != "" {
		body += ` <a href="` + html.EscapeString(link) + `">Why? Click for details.</a>`
	}
	_, _ = w.Write([]byte(body + "</p>\n"))
}
