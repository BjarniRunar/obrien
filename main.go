// Command police is a minimal, high-performance reverse HTTP proxy that can
// serve cleartext HTTP and terminate TLS simultaneously.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	var (
		upstream  = flag.String("upstream", "http://127.0.0.1:8080", "upstream base URL")
		httpAddr  = flag.String("http", ":8000", "cleartext listen address (empty to disable)")
		httpsAddr = flag.String("https", "", "TLS listen address (empty to disable)")
		certFile  = flag.String("cert", "", "TLS certificate file (PEM)")
		keyFile   = flag.String("key", "", "TLS private key file (PEM)")
	)
	flag.Parse()

	target, err := url.Parse(*upstream)
	if err != nil || target.Scheme == "" || target.Host == "" {
		log.Fatalf("invalid -upstream %q", *upstream)
	}
	if *httpAddr == "" && *httpsAddr == "" {
		log.Fatal("at least one of -http or -https must be set")
	}
	if *httpsAddr != "" && (*certFile == "" || *keyFile == "") {
		log.Fatal("-https requires -cert and -key")
	}

	handler := newProxy(target)

	var servers []*http.Server
	errc := make(chan error, 2)

	if *httpAddr != "" {
		srv := newServer(*httpAddr, handler)
		servers = append(servers, srv)
		go func() {
			log.Printf("listening for HTTP on %s -> %s", *httpAddr, target)
			errc <- srv.ListenAndServe()
		}()
	}
	if *httpsAddr != "" {
		srv := newServer(*httpsAddr, handler)
		srv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1"},
		}
		servers = append(servers, srv)
		go func() {
			log.Printf("listening for HTTPS on %s -> %s", *httpsAddr, target)
			errc <- srv.ListenAndServeTLS(*certFile, *keyFile)
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Printf("server error: %v", err)
		}
	case s := <-sig:
		log.Printf("received %s, shutting down", s)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(ctx)
	}
}

func newProxy(target *url.URL) http.Handler {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
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
			r.SetXForwarded()
			r.Out.Host = r.In.Host // preserve the client's Host header
		},
		Transport:     transport,
		FlushInterval: -1, // flush immediately; good for streaming/SSE
		BufferPool:    newBufferPool(),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy error: %s %s: %v", r.Method, r.URL, err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
}

func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}
