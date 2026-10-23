// SPDX-License-Identifier: AGPL-3.0-or-later

// Package monitor observes every proxied request and passes a summary of it
// to hooks, such as metrics or the in-memory request log.
package monitor

import (
	"net/http"
	"time"

	"obrien/proxy"
)

// Record summarises one request and its response.
type Record struct {
	Time       time.Time     `msgpack:"time" json:"time"`
	Listener   string        `msgpack:"listener" json:"listener"`
	RemoteAddr string        `msgpack:"remote_addr" json:"remote_addr"`
	Method     string        `msgpack:"method" json:"method"`
	Host       string        `msgpack:"host" json:"host"`
	URI        string        `msgpack:"uri" json:"uri"`
	Proto      string        `msgpack:"proto" json:"proto"`
	Status     int           `msgpack:"status" json:"status"`
	Duration   time.Duration `msgpack:"duration" json:"duration"`
	Blocked    bool          `msgpack:"blocked" json:"blocked,omitempty"`
	Malformed  bool          `msgpack:"malformed" json:"malformed,omitempty"`
	Trace      string        `msgpack:"trace" json:"trace,omitempty"`
}

// Hook receives a Record for each completed request. Hooks run on the
// request's goroutine after the response is written, so they must be fast
// and safe for concurrent use.
type Hook interface {
	Observe(rec *Record)
}

// HookFunc adapts a function to Hook.
type HookFunc func(rec *Record)

func (f HookFunc) Observe(rec *Record) { f(rec) }

// TimeFunc is called after the hooks for each request, with the time they
// took to run.
type TimeFunc func(listener string, d time.Duration)

// Annotator is called before each request is handled, and may return a
// replacement request (e.g. with a new context or body) for next. The
// function it returns, if not nil, is called after the response to add to
// the Record, before the hooks see it.
type Annotator func(r *http.Request) (*http.Request, func(rec *Record))

// Middleware wraps next, building a Record for every request it handles and
// passing it to each hook in order. annotate may be nil.
func Middleware(listener string, hooks []Hook, annotate Annotator, onTime TimeFunc, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		var finish func(rec *Record)
		if annotate != nil {
			r, finish = annotate(r)
		}
		sw := proxy.NewStatusWriter(w)
		next.ServeHTTP(sw, r)
		rec := &Record{
			Time:       start,
			Listener:   listener,
			RemoteAddr: r.RemoteAddr,
			Method:     r.Method,
			Host:       r.Host,
			URI:        r.RequestURI,
			Proto:      r.Proto,
			Status:     sw.Status,
			Duration:   time.Since(start),
		}
		hookStart := time.Now()
		if finish != nil {
			finish(rec)
		}
		for _, h := range hooks {
			h.Observe(rec)
		}
		if onTime != nil {
			onTime(listener, time.Since(hookStart))
		}
	})
}
