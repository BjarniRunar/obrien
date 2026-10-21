package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/mailpile/kettlingar-go/kettlingar"

	"police/monitor"
	"police/proxy"
	"police/rules"
)

// off disables a listener or file setting. kettlingar only exposes settings
// with a non-empty default, so "off" stands in for "unset".
const off = "off"

// Police is the kettlingar service. Fields tagged with `default` and `help`
// are settings, configurable via "police start" flags, POLICE_* environment
// variables or the police.yaml config file.
type Police struct {
	Upstream      string `default:"http://127.0.0.1:80" help:"Upstream base URL"`
	UpstreamHttps string `default:"https://127.0.0.1:443" help:"Upstream base URL for the TLS listener"`
	Http          string `default:":8000" help:"Cleartext listen address, or off"`
	Https         string `default:"off"   help:"TLS listen address, or off"`
	Cert          string `default:"off"   help:"TLS certificate file (PEM)"`
	Key           string `default:"off"   help:"TLS private key file (PEM)"`

	RequestLog int `default:"1000" help:"Recent requests kept in memory, or 0"`

	ks            *kettlingar.KettlingarService
	servers       []*http.Server
	upstream      *url.URL
	upstreamHttps *url.URL
	hooks         []monitor.Hook
	log           *monitor.Log
	httpLn        net.Listener
	httpsLn       net.Listener
}

// ServiceStartup runs in the daemon before kettlingar signals readiness, so
// listeners are bound here: a bad address or certificate makes "police start"
// fail instead of leaving a half-working daemon behind.
func (p *Police) ServiceStartup(ks *kettlingar.KettlingarService) error {
	p.ks = ks

	target, err := parseUpstream(p.Upstream)
	if err != nil {
		return err
	}
	targetHttps, err := parseUpstream(p.UpstreamHttps)
	if err != nil {
		return err
	}
	if p.Http == off && p.Https == off {
		return errors.New("at least one of --http or --https must be enabled")
	}

	ks.MetricsHelp("proxy_connections_total", "Client connections accepted, by listener", kettlingar.PublicMetric)
	ks.MetricsHelp("proxy_requests_total", "Proxied requests by listener and status", kettlingar.PublicMetric)
	ks.MetricsHelp("proxy_request_time_us", "Proxied request time in microseconds", kettlingar.PublicMetric)
	ks.MetricsHelp("proxy_upstream_errors_total", "Requests that failed to reach the upstream", kettlingar.PublicMetric)
	ks.MetricsHelp("rules_rejected_total", "Requests rejected by rules", kettlingar.PublicMetric)

	p.hooks = []monitor.Hook{monitor.HookFunc(p.recordMetrics)}
	if p.RequestLog > 0 {
		p.log = monitor.NewLog(p.RequestLog)
		p.hooks = append(p.hooks, p.log)
	}

	p.upstream = target
	p.upstreamHttps = targetHttps

	if p.Http != off {
		ln, err := net.Listen("tcp", p.Http)
		if err != nil {
			return fmt.Errorf("listen http: %w", err)
		}
		p.httpLn = ln
		p.serve("http", proxy.NewServer(monitor.Middleware("http", p.hooks, p.pipeline(target))), ln)
	}
	if p.Https != off {
		if p.Cert == off || p.Key == off {
			return errors.New("--https requires --cert and --key")
		}
		cert, err := tls.LoadX509KeyPair(p.Cert, p.Key)
		if err != nil {
			return fmt.Errorf("load TLS keypair: %w", err)
		}
		ln, err := net.Listen("tcp", p.Https)
		if err != nil {
			return fmt.Errorf("listen https: %w", err)
		}
		p.httpsLn = ln
		srv := proxy.NewServer(monitor.Middleware("https", p.hooks, p.pipeline(targetHttps)))
		srv.TLSConfig = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"},
			Certificates: []tls.Certificate{cert},
		}
		p.serve("https", srv, tls.NewListener(ln, srv.TLSConfig))
	}
	return nil
}

func (p *Police) GetDocs() map[string]kettlingar.MethodDesc {
	return map[string]kettlingar.MethodDesc{
		"firewall-on": {
			Help: "Redirect incoming TCP 80/443 to police's listeners",
			Docs: "Installs nftables rules redirecting ports 80 and 443 to the ports police is\n" +
				"listening on. With --local true, connections made on this host are\n" +
				"redirected too. If the upstream is on port 80 or 443, connections from the\n" +
				"daemon's own user are exempt, so police does not loop into itself.",
		},
		"firewall-off":    {Help: "Remove police's firewall redirect"},
		"firewall-status": {Help: "Show police's firewall redirect rules"},
		"requests":        {Help: "Show recently proxied requests"},
	}
}

func (p *Police) pipeline(target *url.URL) http.Handler {
	return rules.Filter(nil, p.rejected, proxy.New(target, p.upstreamError))
}

func parseUpstream(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid upstream %q", raw)
	}
	return u, nil
}

// serve counts connections as they are accepted, before any TLS handshake or
// request, so traffic that reaches police shows up in metrics even when no
// request completes.
func (p *Police) serve(listener string, srv *http.Server, ln net.Listener) {
	labels := kettlingar.MetricLabels{"listener": listener}
	srv.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			p.ks.MetricsCount("proxy_connections_total", 1, kettlingar.PublicMetric, labels)
		}
	}
	p.servers = append(p.servers, srv)
	p.ks.Logger.Info(serviceName+": proxying", "listener", listener, "listen", ln.Addr().String())
	go func() {
		if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			p.ks.Logger.Error(serviceName+": proxy server error", "err", err)
		}
	}()
}

func (p *Police) ServiceShutdown(ks *kettlingar.KettlingarService) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, srv := range p.servers {
		_ = srv.Shutdown(ctx)
	}
	return nil
}

func (p *Police) upstreamError(r *http.Request, err error) {
	p.ks.Logger.Warn(serviceName+": upstream error", "method", r.Method, "url", r.URL.String(), "err", err)
	p.ks.MetricsCount("proxy_upstream_errors_total", 1, kettlingar.PublicMetric, nil)
}

func (p *Police) rejected(r *http.Request, err error) {
	p.ks.Logger.Info(serviceName+": request rejected", "method", r.Method, "url", r.URL.String(), "reason", err)
	p.ks.MetricsCount("rules_rejected_total", 1, kettlingar.PublicMetric, nil)
}

func (p *Police) recordMetrics(rec *monitor.Record) {
	labels := kettlingar.MetricLabels{"listener": rec.Listener, "code": fmt.Sprint(rec.Status)}
	p.ks.MetricsCount("proxy_requests_total", 1, kettlingar.PublicMetric, labels)
	p.ks.MetricsSample("proxy_request_time_us", uint64(rec.Duration.Microseconds()),
		kettlingar.PublicMetric, kettlingar.MetricLabels{"listener": rec.Listener})
}
