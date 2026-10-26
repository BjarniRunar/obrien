// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mailpile/kettlingar-go/kettlingar"
)

type CertsResponse struct {
	Certs []CertEntry `msgpack:"certs" json:"certs"`
	Error string      `msgpack:"error" json:"error,omitempty"`
}

// CertEntry is one certificate file. Error is its last load failure; if
// Names is set, the previously loaded certificate is still being served.
type CertEntry struct {
	Path     string    `msgpack:"path" json:"path"`
	Names    []string  `msgpack:"names" json:"names"`
	NotAfter time.Time `msgpack:"not_after" json:"not_after"`
	Default  bool      `msgpack:"default" json:"default,omitempty"`
	Error    string    `msgpack:"error" json:"error,omitempty"`
}

func (r *CertsResponse) String() string {
	if r.Error != "" {
		return "error: " + r.Error
	}
	if len(r.Certs) == 0 {
		return "(no certificates)"
	}
	var b strings.Builder
	now := time.Now()
	for _, c := range r.Certs {
		fmt.Fprintf(&b, "%s\n", c.Path)
		if len(c.Names) > 0 {
			expiry := c.NotAfter.Format("2006-01-02")
			switch days := int(c.NotAfter.Sub(now).Hours() / 24); {
			case c.NotAfter.Before(now):
				expiry += " (EXPIRED)"
			case days < 14:
				expiry += fmt.Sprintf(" (%d days left)", days)
			}
			fmt.Fprintf(&b, "  names:   %s\n  expires: %s\n", strings.Join(c.Names, ", "), expiry)
		}
		if c.Default {
			b.WriteString("  default\n")
		}
		if c.Error != "" {
			fmt.Fprintf(&b, "  error:   %s\n", c.Error)
		}
	}
	return b.String()
}

func (p *Obrien) ApiCertsList(ri *kettlingar.RequestInfo) *CertsResponse {
	if p.certs == nil {
		ri.HttpCode = http.StatusNotFound
		return &CertsResponse{Error: "no TLS listener"}
	}
	p.certs.maybeReload()
	var entries []CertEntry
	for _, ci := range p.certs.list() {
		e := CertEntry{Path: ci.Path, Names: ci.Names, NotAfter: ci.NotAfter, Default: ci.Default}
		if ci.Err != nil {
			e.Error = ci.Err.Error()
		}
		entries = append(entries, e)
	}
	return &CertsResponse{Certs: entries}
}
