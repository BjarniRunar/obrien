// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"obrien/monitor"
	"obrien/rules"
)

func TestTracesOnlySuccess(t *testing.T) {
	log := monitor.NewLog(10)
	p := &Obrien{log: log}
	for status, traced := range map[int]bool{200: true, 204: true, 302: true, 304: true, 404: false, 502: false, 503: false} {
		backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) })
		h := monitor.Middleware("http", []monitor.Hook{log}, p.annotator(), nil,
			rules.Filter(nil, http.StatusForbidden, "", nil, nil, backend))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/a", nil))
		rec := log.Recent(1)[0]
		if (rec.Trace != "") != traced {
			t.Errorf("status %d: trace %q", status, rec.Trace)
		}
	}
}
