// Package proxy forwards HTTP requests to a single upstream. It knows nothing
// about inspecting or filtering traffic; that is the job of package rules.
package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

// ErrorFunc is called when a request cannot be forwarded to the upstream.
// The client has already been sent a 502 by the time it runs.
type ErrorFunc func(r *http.Request, err error)

// New returns a reverse proxy to target, tuned for many concurrent clients.
//
// For an https target, the TLS connection to the upstream uses the name the
// client asked for (its SNI, else its Host), and the upstream's certificate
// is verified against that name rather than against target's host, which is
// usually a local address. Connections are always dialled to target's host.
func New(target *url.URL, onError ErrorFunc) http.Handler {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	upstreamAddr := target.Host
	if target.Port() == "" {
		upstreamAddr = net.JoinHostPort(target.Hostname(), defaultPort(target.Scheme))
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, upstreamAddr)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1024,
		MaxIdleConnsPerHost:   1024,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	return &httputil.ReverseProxy{
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
