// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"obrien/monitor"
	"obrien/rules"
)

func TestTracesBelow500(t *testing.T) {
	p := &Obrien{log: monitor.NewLog(10)}
	var rec *monitor.Record
	last := monitor.HookFunc(func(r *monitor.Record) { rec = r })
	for status, traced := range map[int]bool{200: true, 204: true, 302: true, 304: true, 400: true, 404: true, 502: false, 503: false} {
		backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) })
		h := monitor.Middleware("http", []monitor.Hook{last}, p.annotator(), nil,
			rules.Filter(nil, http.StatusForbidden, "", nil, nil, backend))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/a", nil))
		if (rec.Trace != "") != traced {
			t.Errorf("status %d: trace %q", status, rec.Trace)
		}
	}
}

type rejectAll struct{}

func (rejectAll) Check(*http.Request) error { return errors.New("no") }

func TestBlockedMarked(t *testing.T) {
	p := &Obrien{log: monitor.NewLog(10)}
	var rec *monitor.Record
	last := monitor.HookFunc(func(r *monitor.Record) { rec = r })
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })
	for _, c := range []struct {
		rule               rules.Rule
		blocked, malformed bool
	}{
		{nil, false, false},
		{rejectAll{}, true, false},
		{rules.Sanity{}, true, true},
	} {
		var list []rules.Rule
		if c.rule != nil {
			list = append(list, c.rule)
		}
		h := monitor.Middleware("http", []monitor.Hook{last}, p.annotator(), nil,
			rules.Filter(list, http.StatusForbidden, "", nil, nil, backend))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/a", nil))
		if rec.Status != http.StatusForbidden || rec.Blocked != c.blocked || rec.Malformed != c.malformed {
			t.Errorf("rule %T: %+v", c.rule, rec)
		}
	}
}
