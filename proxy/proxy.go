// SPDX-License-Identifier: AGPL-3.0-or-later

// Package proxy forwards HTTP requests to a single upstream. It knows nothing
// about inspecting or filtering traffic; that is the job of package rules.
package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ErrorFunc is called when a request cannot be forwarded to the upstream.
// The client has already been sent a 502 by the time it runs.
type ErrorFunc func(r *http.Request, err error)

// Proxy is a reverse proxy to a single upstream.
type Proxy struct {
	rp        *httputil.ReverseProxy
	perClient bool
	clients   sync.Map // client net.Conn -> *clientTransport
}

// New returns a reverse proxy to target, tuned for many concurrent clients.
//
// For an https target, the TLS connection to the upstream uses the name the
// client asked for (its SNI, else its Host), and the upstream's certificate
// is verified against that name rather than against target's host, which is
// usually a local address. Connections are always dialled to target's host.
//
// X-Forwarded-For is set to the client's address. Only when the client is
// in trusted is the X-Forwarded-For it sent kept, with its address appended.
//
// With perClient, upstream connections belong to one client connection:
// reused for its requests only, and closed with it. This is for upstreams
// (such as PageKite relays) that route each connection by its first
// request. HTTP/2 to the upstream is then off, and the server must install
// ConnContext and ConnState.
func New(target *url.URL, trusted []netip.Prefix, perClient bool, onError ErrorFunc) *Proxy {
	upstreamAddr := addrOf(target)
	newTransport := func() *http.Transport {
		t := &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, upstreamAddr)
			},
			ForceAttemptHTTP2:     !perClient,
			MaxIdleConns:          1024,
			MaxIdleConnsPerHost:   1024,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		}
		if perClient {
			t.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		}
		return t
	}

	p := &Proxy{perClient: perClient}
	var transport http.RoundTripper = newTransport()
	if perClient {
		transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			ct, ok := r.Context().Value(clientKey{}).(*clientTransport)
			if !ok {
				return nil, errors.New("request not on a tracked client connection")
			}
			return ct.get(newTransport).RoundTrip(r)
		})
	}
	p.rp = &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			// The transport takes the TLS name from the URL and also keys
			// its connection pool on it, so a pooled connection is only
			// reused for the name it was verified against.
			if target.Scheme == "https" {
				if name := clientServerName(r.In); name != "" {
					r.Out.URL.Host = net.JoinHostPort(name, defaultPort("https"))
				}
			}
			// ReverseProxy strips X-Forwarded-For from Out before Rewrite.
			if xff := r.In.Header.Values("X-Forwarded-For"); len(xff) > 0 && isTrusted(r.In, trusted) {
				r.Out.Header["X-Forwarded-For"] = xff
			}
			r.SetXForwarded()
			r.Out.Host = r.In.Host // preserve the client's Host header
		},
		Transport:     transport,
		FlushInterval: -1, // flush immediately; good for streaming/SSE
		BufferPool:    newBufferPool(),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			w.WriteHeader(http.StatusBadGateway)
			if onError != nil {
				onError(r, err)
			}
		},
	}
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) { p.rp.ServeHTTP(w, r) }

type clientKey struct{}

// ConnContext gives each client connection its own upstream connections when
// perClient; install it as (or chain it from) the http.Server's ConnContext.
func (p *Proxy) ConnContext(ctx context.Context, c net.Conn) context.Context {
	if !p.perClient {
		return ctx
	}
	ct := &clientTransport{}
	p.clients.Store(c, ct)
	return context.WithValue(ctx, clientKey{}, ct)
}

// ConnState closes a client's upstream connections when it closes or is
// hijacked; install it as the http.Server's ConnState.
func (p *Proxy) ConnState(c net.Conn, state http.ConnState) {
	if state != http.StateClosed && state != http.StateHijacked {
		return
	}
	if ct, ok := p.clients.LoadAndDelete(c); ok {
		ct.(*clientTransport).close()
	}
}

// clientTransport is one client connection's upstream connection pool,
// created on its first request. Connections in use when the client closes
// return to a closed pool and are dropped by IdleConnTimeout.
type clientTransport struct {
	mu     sync.Mutex
	t      *http.Transport
	closed bool
}

func (ct *clientTransport) get(newTransport func() *http.Transport) *http.Transport {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.t == nil {
		ct.t = newTransport()
		if ct.closed {
			ct.t.DisableKeepAlives = true
		}
	}
	return ct.t
}

func (ct *clientTransport) close() {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.closed = true
	if ct.t != nil {
		ct.t.CloseIdleConnections()
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// ParseTrusted parses a comma-separated list of IP addresses and CIDR
// prefixes.
func ParseTrusted(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(f); err == nil {
			out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
		} else {
			return nil, fmt.Errorf("invalid address or prefix %q", f)
		}
	}
	return out, nil
}

func isTrusted(r *http.Request, trusted []netip.Prefix) bool {
	if len(trusted) == 0 {
		return false
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	addr := ap.Addr().Unmap()
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// clientServerName returns the host name the client asked for, or "" if it
// gave only an IP address.
func clientServerName(r *http.Request) string {
	if r.TLS != nil && r.TLS.ServerName != "" {
		return r.TLS.ServerName
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	return host
}

var dialer = &net.Dialer{
	Timeout:   5 * time.Second,
	KeepAlive: 30 * time.Second,
}

// addrOf returns target's host:port, with the scheme's default port.
func addrOf(target *url.URL) string {
	if target.Port() == "" {
		return net.JoinHostPort(target.Hostname(), defaultPort(target.Scheme))
	}
	return target.Host
}

func defaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}

// NewServer returns an http.Server with timeouts suitable for facing
// untrusted clients.
func NewServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}
