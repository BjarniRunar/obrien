// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mailpile/kettlingar-go/kettlingar"

	"obrien/monitor"
	"obrien/proxy"
	"obrien/rules"
	"obrien/trace"
)

// off disables a listener or file setting. kettlingar only exposes settings
// with a non-empty default, so "off" stands in for "unset".
const off = "off"

// traceLogRotate is the bytes written to the trace log before it is rotated.
const traceLogRotate = 20 << 20

// Obrien is the kettlingar service. Fields tagged with `default` and `help`
// are settings, configurable via "obrien start" flags, OBRIEN_* environment
// variables or the obrien.yaml config file.
type Obrien struct {
	Upstream      string `default:"http://127.0.0.1:80" help:"Upstream base URL"`
	UpstreamHttps string `default:"https://127.0.0.1:443" help:"Upstream base URL for the TLS listener"`
	Http          string `default:":9080" help:"Cleartext listen address, or off"`
	Https         string `default:":9443" help:"TLS listen address (used once --cert and --key are set), or off"`
	Cert          string `default:"off"   help:"TLS certificate file (PEM)"`
	Key           string `default:"off"   help:"TLS private key file (PEM)"`
	TlsKeys       string `default:"off"   help:"Comma-separated PEM files holding a certificate chain and key, or directories of them; chosen by SNI"`

	BlockedStatus int    `default:"502" help:"HTTP status for requests blocked by rules (400-599)"`
	BlockedUrl    string `default:"off" help:"Page linked from block responses explaining blocks, unless the rule sets its own, or off"`

	Crs         string `default:"off" help:"OWASP Core Rule Set: block, detect (log only) or off"`
	CrsParanoia int    `default:"1"   help:"CRS paranoia level, 1-4"`
	CrsConf     string `default:"off" help:"Absolute path of extra CRS directives (tuning, exclusions), or off"`

	TrustedProxies string `default:"off" help:"Comma-separated IPs/CIDRs whose X-Forwarded-For is kept, or off"`
	AllowPagekite  bool   `default:"false" help:"Pass PageKite handshakes and CONNECTs to the upstream unmodified and uninspected"`

	RequestLog int    `default:"1000" help:"Recent requests kept in memory, or 0"`
	TraceLog   string `default:"off"  help:"Absolute path of a file to append a line per request to, with its trace, or off; rotated every 20 MB"`

	ks            *kettlingar.KettlingarService
	servers       []*http.Server
	upstream      *url.URL
	upstreamHttps *url.URL
	certs         *certStore
	hooks         []monitor.Hook
	log           *monitor.Log
	traceFile     *monitor.RotatingFile
	httpLn        net.Listener
	httpsLn       net.Listener
	patterns      *rules.Patterns
	crs           *rules.CRS
	trusted       []netip.Prefix
}

// ServiceStartup runs in the daemon before kettlingar signals readiness, so
// listeners are bound here: a bad address or certificate makes "obrien start"
// fail instead of leaving a half-working daemon behind.
func (p *Obrien) ServiceStartup(ks *kettlingar.KettlingarService) error {
	p.ks = ks

	target, err := parseUpstream(p.Upstream)
	if err != nil {
		return err
	}
	targetHttps, err := parseUpstream(p.UpstreamHttps)
	if err != nil {
		return err
	}
	if p.TrustedProxies != off {
		if p.trusted, err = proxy.ParseTrusted(p.TrustedProxies); err != nil {
			return fmt.Errorf("--trusted-proxies: %w", err)
		}
	}
	if p.BlockedStatus < 400 || p.BlockedStatus > 599 {
		return fmt.Errorf("--blocked-status %d: must be 400-599", p.BlockedStatus)
	}
	if p.BlockedUrl != off {
		if err := rules.ValidURL(p.BlockedUrl); err != nil {
			return fmt.Errorf("--blocked-url: %w", err)
		}
	}
	if (p.Cert == off) != (p.Key == off) {
		return errors.New("--cert and --key must be given together")
	}
	// --https has a default address, so without a certificate the TLS
	// listener is simply not started rather than being an error.
	https := p.Https
	if p.Cert == off && p.TlsKeys == off {
		https = off
	}
	if p.Http == off && https == off {
		return errors.New("no listener enabled: set --http, or --cert and --key or --tls-keys for --https")
	}

	ks.MetricsHelp("proxy_connections_total", "Client connections accepted, by listener", kettlingar.PublicMetric)
	ks.MetricsHelp("proxy_requests_total", "Proxied requests by listener and status", kettlingar.PublicMetric)
	ks.MetricsHelp("proxy_request_time_us", "Proxied request time in microseconds", kettlingar.PublicMetric)
	ks.MetricsHelp("proxy_upstream_errors_total", "Requests that failed to reach the upstream", kettlingar.PublicMetric)
	ks.MetricsHelp("proxy_tunnels_total", "Connections tunnelled unmodified (PageKite, CONNECT), by listener", kettlingar.PublicMetric)
	ks.MetricsHelp("proxy_tls_passthrough_total", "TLS connections passed on encrypted, for names without a certificate, by listener", kettlingar.PublicMetric)
	ks.MetricsHelp("rules_rejected_total", "Requests rejected by rules", kettlingar.PublicMetric)
	ks.MetricsHelp("rules_checked_total", "Requests checked against rules", kettlingar.PublicMetric)
	ks.MetricsHelp("rules_invalid_total", "Requests rejected by the header sanity check", kettlingar.PublicMetric)
	ks.MetricsHelp("rules_matched_total", "Requests whose header matched a pattern, by rule", kettlingar.PublicMetric)
	ks.MetricsHelp("rules_detected_total", "Requests the CRS would have rejected, with --crs detect", kettlingar.PublicMetric)
	ks.MetricsHelp("rules_crs_rejected_total", "Requests rejected by the CRS", kettlingar.PublicMetric)
	ks.MetricsHelp("rules_crs_errors_total", "Errors met while running the CRS, by type", kettlingar.PublicMetric)
	ks.MetricsHelp("rules_crs_check_time_us", "Time spent running the CRS per request, including reading the body, in microseconds", kettlingar.PublicMetric)
	ks.MetricsHelp("rules_check_time_us", "Time spent running rules per request, in microseconds", kettlingar.PublicMetric)
	ks.MetricsHelp("monitor_hooks_total", "Requests whose Record was passed to the monitor hooks, by listener", kettlingar.PublicMetric)
	ks.MetricsHelp("monitor_hook_time_us", "Time spent running monitor hooks per request, in microseconds", kettlingar.PublicMetric)

	p.hooks = []monitor.Hook{monitor.HookFunc(p.recordMetrics)}
	if p.RequestLog > 0 {
		p.log = monitor.NewLog(p.RequestLog)
		p.hooks = append(p.hooks, p.log)
	}
	if p.TraceLog != off {
		// The daemon's working directory is not the caller's.
		if !filepath.IsAbs(p.TraceLog) {
			return fmt.Errorf("--trace-log %q must be an absolute path", p.TraceLog)
		}
		f, err := monitor.OpenRotatingFile(p.TraceLog, traceLogRotate)
		if err != nil {
			return fmt.Errorf("--trace-log: %w", err)
		}
		p.traceFile = f
		p.hooks = append(p.hooks, monitor.NewTraceLog(f))
	}

	p.patterns = rules.NewPatterns(p.patternMatched)
	if err := p.startCRS(); err != nil {
		return err
	}
	p.upstream = target
	p.upstreamHttps = targetHttps

	if p.Http != off {
		ln, err := net.Listen("tcp", p.Http)
		if err != nil {
			return fmt.Errorf("listen http: %w", err)
		}
		p.httpLn = ln
		px := proxy.New(target, p.trusted, p.AllowPagekite, p.upstreamError)
		srv := proxy.NewServer(monitor.Middleware("http", p.hooks, p.annotator(), p.hooksTimed, p.pipeline(px)))
		p.serve("http", srv, ln, nil, target, px)
	}
	if https != off {
		pairCert, pairKey, keyPaths := p.Cert, p.Key, []string(nil)
		if p.Cert == off {
			pairCert, pairKey = "", ""
		}
		if p.TlsKeys != off {
			keyPaths = splitPaths(p.TlsKeys)
		}
		certs, err := newCertStore(pairCert, pairKey, keyPaths, func(path string, err error) {
			p.ks.Logger.Warn(serviceName+": TLS certificate not loaded", "path", path, "err", err)
		})
		if err != nil {
			return fmt.Errorf("load TLS certificates: %w", err)
		}
		p.certs = certs
		ln, err := net.Listen("tcp", https)
		if err != nil {
			return fmt.Errorf("listen https: %w", err)
		}
		p.httpsLn = ln
		px := proxy.New(targetHttps, p.trusted, p.AllowPagekite, p.upstreamError)
		srv := proxy.NewServer(monitor.Middleware("https", p.hooks, p.annotator(), p.hooksTimed, p.pipeline(px)))
		srv.TLSConfig = &tls.Config{
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{"h2", "http/1.1"},
			GetCertificate: certs.GetCertificate,
		}
		// An HTTP/2 client may send requests for several sites over one
		// connection, which a PageKite relay would route by the first.
		if p.AllowPagekite {
			srv.TLSConfig.NextProtos = []string{"http/1.1"}
		}
		p.serve("https", srv, ln, srv.TLSConfig, targetHttps, px)
	}
	return nil
}

func (p *Obrien) GetDocs() map[string]kettlingar.MethodDesc {
	return map[string]kettlingar.MethodDesc{
		"firewall-on": {
			Help: "Print commands redirecting incoming TCP 80/443 to obrien",
			Docs: "Prints, without running, a shell script redirecting ports 80 and 443 to the ports obrien is\n" +
				"listening on, using nft if in /usr/sbin, else iptables/ip6tables; --mode\n" +
				"nft or iptables picks one. With --local true, connections made on this host are\n" +
				"redirected too. If an upstream is on a redirected port, connections from the\n" +
				"daemon's own user are exempt, so obrien does not loop into itself.",
		},
		"firewall-off":    {Help: "Print commands removing obrien's firewall redirect"},
		"firewall-status": {Help: "Print commands showing obrien's firewall redirect rules"},
		"requests":        {Help: "Show recently proxied requests"},
		"certs-list": {
			Help: "Show loaded TLS certificates: file, names, expiry",
			Docs: "Lists each certificate file in load order, marking the default (served\n" +
				"when no name matches) and files that failed to load; a failed file keeps\n" +
				"serving its previous certificate. Files are rechecked first, at most once\n" +
				"a minute.",
		},
		"rules-list": {
			Help: "Show the header patterns requests are rejected by",
			Docs: "Lists the patterns in the order they are tried. Use -f json to save them in\n" +
				"the format rules-add --file reads.",
		},
		"rules-add": {
			Help: "Add a header pattern: [--url URL] NAME REGEXP, or --file",
			Docs: "rules-add NAME REGEXP adds a pattern; a request whose raw header matches it\n" +
				"is rejected. The header is matched as sent, request line and CRLFs included;\n" +
				"use (?i) for case-insensitive and (?m) for per-line ^ and $.\n\n" +
				"--url URL sets the page linked from the block response to explain the block,\n" +
				"instead of --blocked-url: an http(s) URL or an absolute path.\n\n" +
				"--replace OLD puts the new pattern in OLD's place. --file PATH loads the\n" +
				"patterns in a file written by rules-list -f json: ones named like an\n" +
				"existing rule replace it in place, the rest are added. PATH is read by\n" +
				"the daemon and must be absolute. Nothing is changed if any pattern is invalid.",
		},
		"rules-rm": {Help: "Remove header patterns by name: NAME..."},
	}
}

func (p *Obrien) pipeline(px *proxy.Proxy) http.Handler {
	infoURL := p.BlockedUrl
	if infoURL == off {
		infoURL = ""
	}
	list := []rules.Rule{rules.Sanity{}, p.patterns}
	if p.crs != nil {
		list = append(list, p.crs)
	}
	return rules.Filter(list, p.BlockedStatus, infoURL, p.rejected, p.rulesTimed, px)
}

func parseUpstream(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid upstream %q", raw)
	}
	return u, nil
}

// serve counts connections as they are accepted, before any TLS handshake or
// request, so traffic that reaches obrien shows up in metrics even when no
// request completes.
func (p *Obrien) serve(listener string, srv *http.Server, ln net.Listener, tlsConfig *tls.Config, target *url.URL, px *proxy.Proxy) {
	labels := kettlingar.MetricLabels{"listener": listener}
	counted := countingListener{ln, func() {
		p.ks.MetricsCount("proxy_connections_total", 1, kettlingar.PublicMetric, labels)
	}}
	srv.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return px.ConnContext(rules.ConnContext(ctx, c), c)
	}
	srv.ConnState = px.ConnState
	p.servers = append(p.servers, srv)
	p.ks.Logger.Info(serviceName+": proxying", "listener", listener, "listen", ln.Addr().String())
	go func() {
		if err := srv.Serve(rules.Listen(counted, tlsConfig, srv.MaxHeaderBytes, p.tunnel(listener, target), p.passthrough(listener, tlsConfig, target))); !errors.Is(err, http.ErrServerClosed) {
			p.ks.Logger.Error(serviceName+": proxy server error", "err", err)
		}
	}()
}

func (p *Obrien) ServiceShutdown(ks *kettlingar.KettlingarService) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, srv := range p.servers {
		_ = srv.Shutdown(ctx)
	}
	if p.crs != nil {
		_ = p.crs.Close()
	}
	if p.traceFile != nil {
		_ = p.traceFile.Close()
	}
	return nil
}

// annotator traces each request for the request log and trace log; without
// either there is nothing to trace for. Only requests answered with 2xx, 3xx or
// 4xx are traced, so requests the rules blocked are traced only when
// --blocked-status is 4xx.
func (p *Obrien) annotator() monitor.Annotator {
	if p.log == nil && p.traceFile == nil {
		return nil
	}
	return func(r *http.Request) (*http.Request, func(*monitor.Record)) {
		ctx, slot := rules.WithHeaderSlot(r.Context())
		r = r.WithContext(ctx)
		var body *trace.Body
		if r.Body != nil && r.Body != http.NoBody {
			body = trace.NewBody(r.Body, r.Header.Get("Content-Type"))
			r.Body = body
		}
		return r, func(rec *monitor.Record) {
			rec.Blocked = slot.Blocked()
			rec.Malformed = slot.Malformed()
			if rec.Status >= 200 && rec.Status < 500 {
				rec.Trace = trace.Of(slot.Header(), body)
			}
		}
	}
}

func (p *Obrien) startCRS() error {
	if p.Crs == off {
		return nil
	}
	if p.Crs != "block" && p.Crs != "detect" {
		return fmt.Errorf("--crs %q: use block, detect or off", p.Crs)
	}
	cfg := rules.CRSConfig{
		Block:    p.Crs == "block",
		Paranoia: p.CrsParanoia,
		OnMatch:  p.patternMatched,
		OnDetect: p.crsDetected,
		OnTime:   p.crsTimed,
		OnError:  p.crsError,
	}
	if p.CrsConf != off {
		// The daemon's working directory is not the caller's.
		if !filepath.IsAbs(p.CrsConf) {
			return fmt.Errorf("--crs-conf %q must be an absolute path", p.CrsConf)
		}
		data, err := os.ReadFile(p.CrsConf)
		if err != nil {
			return fmt.Errorf("--crs-conf: %w", err)
		}
		cfg.Directives = string(data)
	}
	crs, err := rules.NewCRS(cfg)
	if err != nil {
		return fmt.Errorf("--crs: %w", err)
	}
	p.crs = crs
	return nil
}

func (p *Obrien) crsDetected(r *http.Request, err error) {
	p.ks.Logger.Info(serviceName+": request would be rejected", "method", r.Method, "url", r.URL.String(), "reason", err)
	p.ks.MetricsCount("rules_detected_total", 1, kettlingar.PublicMetric, nil)
}

func (p *Obrien) crsError(r *http.Request, kind string, err error) {
	p.ks.Logger.Info(serviceName+": crs error", "type", kind, "method", r.Method, "url", r.URL.String(), "err", err)
	p.ks.MetricsCount("rules_crs_errors_total", 1, kettlingar.PublicMetric, kettlingar.MetricLabels{"type": kind})
}

func (p *Obrien) crsTimed(_ *http.Request, d time.Duration) {
	p.ks.MetricsSample("rules_crs_check_time_us", uint64(d.Microseconds()), kettlingar.PublicMetric, nil)
}

func (p *Obrien) upstreamError(r *http.Request, err error) {
	p.ks.Logger.Warn(serviceName+": upstream error", "method", r.Method, "url", r.URL.String(), "err", err)
	p.ks.MetricsCount("proxy_upstream_errors_total", 1, kettlingar.PublicMetric, nil)
}

// tunnel returns the listener's PageKite/CONNECT tunnel, or nil when
// --allow-pagekite is off. Tunnels bypass net/http, so they are only counted
// and logged, never recorded as requests.
func (p *Obrien) tunnel(listener string, target *url.URL) rules.TunnelFunc {
	if !p.AllowPagekite {
		return nil
	}
	labels := kettlingar.MetricLabels{"listener": listener}
	t := proxy.Tunnel(target, func(c net.Conn, err error) {
		p.ks.Logger.Warn(serviceName+": tunnel upstream error", "remote", c.RemoteAddr().String(), "err", err)
		p.ks.MetricsCount("proxy_upstream_errors_total", 1, kettlingar.PublicMetric, nil)
	})
	return func(c net.Conn, head []byte) {
		line, _, _ := bytes.Cut(head, []byte("\n"))
		p.ks.Logger.Info(serviceName+": tunnel", "listener", listener, "remote", c.RemoteAddr().String(), "request", strings.TrimSpace(string(line)))
		p.ks.MetricsCount("proxy_tunnels_total", 1, kettlingar.PublicMetric, labels)
		t(c, head)
	}
}

// passthrough returns the TLS listener's check for connections to pass to
// the upstream still encrypted: SNI names no certificate covers, and no SNI
// at all, as sent by old PageKite clients the relay may still support. Nil
// when --allow-pagekite is off.
func (p *Obrien) passthrough(listener string, tlsConfig *tls.Config, target *url.URL) rules.PassthroughFunc {
	if !p.AllowPagekite || tlsConfig == nil {
		return nil
	}
	labels := kettlingar.MetricLabels{"listener": listener}
	t := proxy.RawTunnel(target, func(c net.Conn, err error) {
		p.ks.Logger.Warn(serviceName+": TLS passthrough upstream error", "remote", c.RemoteAddr().String(), "err", err)
		p.ks.MetricsCount("proxy_upstream_errors_total", 1, kettlingar.PublicMetric, nil)
	})
	return func(name string) rules.TunnelFunc {
		if name != "" && p.certs.Has(name) {
			return nil
		}
		return func(c net.Conn, head []byte) {
			p.ks.Logger.Info(serviceName+": TLS passthrough", "listener", listener, "remote", c.RemoteAddr().String(), "sni", name)
			p.ks.MetricsCount("proxy_tls_passthrough_total", 1, kettlingar.PublicMetric, labels)
			t(c, head)
		}
	}
}

func (p *Obrien) rejected(r *http.Request, err error) {
	p.ks.Logger.Info(serviceName+": request rejected", "method", r.Method, "url", r.URL.String(), "reason", err)
	p.ks.MetricsCount("rules_rejected_total", 1, kettlingar.PublicMetric, nil)
	if errors.As(err, new(rules.SanityError)) {
		p.ks.MetricsCount("rules_invalid_total", 1, kettlingar.PublicMetric, nil)
	}
	if errors.As(err, new(rules.CRSError)) {
		p.ks.MetricsCount("rules_crs_rejected_total", 1, kettlingar.PublicMetric, nil)
	}
}

type countingListener struct {
	net.Listener
	onAccept func()
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.onAccept()
	}
	return c, err
}

func (p *Obrien) patternMatched(_ *http.Request, name string) {
	p.ks.MetricsCount("rules_matched_total", 1, kettlingar.PublicMetric, kettlingar.MetricLabels{"rule": name})
}

func (p *Obrien) recordMetrics(rec *monitor.Record) {
	labels := kettlingar.MetricLabels{"listener": rec.Listener, "code": fmt.Sprint(rec.Status)}
	p.ks.MetricsCount("proxy_requests_total", 1, kettlingar.PublicMetric, labels)
	p.ks.MetricsSample("proxy_request_time_us", uint64(rec.Duration.Microseconds()),
		kettlingar.PublicMetric, kettlingar.MetricLabels{"listener": rec.Listener})
}

func (p *Obrien) rulesTimed(_ *http.Request, d time.Duration) {
	p.ks.MetricsCount("rules_checked_total", 1, kettlingar.PublicMetric, nil)
	p.ks.MetricsSample("rules_check_time_us", uint64(d.Microseconds()), kettlingar.PublicMetric, nil)
}

// hooksTimed runs after the hooks, so the time it records includes the
// metrics hook but not itself.
func (p *Obrien) hooksTimed(listener string, d time.Duration) {
	labels := kettlingar.MetricLabels{"listener": listener}
	p.ks.MetricsCount("monitor_hooks_total", 1, kettlingar.PublicMetric, labels)
	p.ks.MetricsSample("monitor_hook_time_us", uint64(d.Microseconds()), kettlingar.PublicMetric, labels)
}
