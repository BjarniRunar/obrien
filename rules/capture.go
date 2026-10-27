// SPDX-License-Identifier: AGPL-3.0-or-later

package rules

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxQueued bounds the headers a connection may parse ahead of the server.
// Only pipelined requests queue up, and a client sending more than this is
// simply cut off from inspection (its later requests are rejected).
const maxQueued = 16

// maxChunkLine bounds a chunk-size line, extensions included.
const maxChunkLine = 4096

const handshakeTimeout = 10 * time.Second

type parseState int

const (
	stHeader parseState = iota
	stBody
	stChunkSize
	stChunkData
	stChunkEnd
	stTrailer
	stDone // stopped: nothing after this point is parsed
)

// captureConn records the raw header of every HTTP/1.x request read through
// it. It follows the stream's message framing (Content-Length and chunked
// bodies) to find where each header starts, independently of net/http's own
// parser. Filter takes the headers in order and checks each matches the
// request net/http produced, so the two parsers cannot silently disagree
// about where a request begins.
type captureConn struct {
	net.Conn
	tls      *tls.ConnectionState
	maxBytes int

	mu      sync.Mutex
	state   parseState
	buf     []byte
	remain  int64 // body or chunk bytes still to skip
	queue   []*Header
	stopErr error
}

func (c *captureConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.feed(p[:n])
		c.mu.Unlock()
	}
	return n, err
}

func (c *captureConn) stop(err error) {
	c.state = stDone
	c.stopErr = err
	c.buf = nil
}

// line takes bytes from p into c.buf up to and including the next LF, and
// returns how many it took and whether a whole line is now buffered.
func (c *captureConn) line(p []byte) (int, bool) {
	if i := bytes.IndexByte(p, '\n'); i >= 0 {
		c.buf = append(c.buf, p[:i+1]...)
		return i + 1, true
	}
	c.buf = append(c.buf, p...)
	return len(p), false
}

func (c *captureConn) feed(p []byte) {
	for len(p) > 0 && c.state != stDone {
		switch c.state {
		case stHeader:
			n, full := c.line(p)
			p = p[n:]
			if len(c.buf) > c.maxBytes {
				c.stop(errors.New("header too large"))
				return
			}
			// The header ends at the first empty line; a bare LF ending is
			// accepted here so it is found, and rejected by parseHeader.
			if full && (bytes.HasSuffix(c.buf, []byte("\n\r\n")) || bytes.HasSuffix(c.buf, []byte("\n\n"))) {
				c.endHeader()
			}

		case stBody, stChunkData:
			n := int64(len(p))
			if n > c.remain {
				n = c.remain
			}
			p = p[n:]
			c.remain -= n
			if c.remain == 0 {
				if c.state == stBody {
					c.state = stHeader
				} else {
					c.state = stChunkEnd
				}
			}

		case stChunkSize, stChunkEnd, stTrailer:
			n, full := c.line(p)
			p = p[n:]
			if len(c.buf) > maxChunkLine {
				c.stop(errors.New("chunk line too long"))
				return
			}
			if full {
				c.endChunkLine()
			}
		}
	}
}

func (c *captureConn) endHeader() {
	h := parseHeader(c.buf)
	c.buf = nil
	if len(c.queue) >= maxQueued {
		c.stop(errors.New("too many pipelined requests"))
		return
	}
	c.queue = append(c.queue, h)
	if h.Err != nil {
		c.stop(h.Err)
		return
	}
	var length int64
	chunked := false
	upgrade := h.Method == "CONNECT"
	for _, f := range h.Fields {
		switch strings.ToLower(f.Name) {
		case "content-length":
			length, _ = strconv.ParseInt(f.Value, 10, 64)
		case "transfer-encoding":
			chunked = true
		case "upgrade":
			upgrade = true
		}
	}
	switch {
	case upgrade:
		// After a successful upgrade the stream is no longer HTTP. If the
		// upgrade is refused, the connection's later requests are uninspected
		// and so rejected.
		c.stop(errors.New("connection upgraded"))
	case chunked:
		c.state = stChunkSize
	case length > 0:
		c.state, c.remain = stBody, length
	default:
		c.state = stHeader
	}
}

func (c *captureConn) endChunkLine() {
	l := c.buf
	c.buf = nil
	if !bytes.HasSuffix(l, []byte("\r\n")) {
		c.stop(errors.New("chunk line not ended by CRLF"))
		return
	}
	l = l[:len(l)-2]
	switch c.state {
	case stChunkEnd:
		if len(l) != 0 {
			c.stop(errors.New("chunk data longer than its size"))
			return
		}
		c.state = stChunkSize
	case stTrailer:
		if len(l) == 0 {
			c.state = stHeader
		}
	case stChunkSize:
		if i := bytes.IndexByte(l, ';'); i >= 0 {
			l = l[:i]
		}
		size, err := strconv.ParseInt(string(bytes.TrimRight(l, " \t")), 16, 64)
		if err != nil || size < 0 {
			c.stop(errors.New("invalid chunk size"))
			return
		}
		if size == 0 {
			c.state = stTrailer
		} else {
			c.state, c.remain = stChunkData, size
		}
	}
}

// next takes the header of the request net/http has just read.
func (c *captureConn) next() *Header {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.queue) == 0 {
		err := c.stopErr
		if err == nil {
			err = errors.New("no header captured")
		}
		return &Header{Err: errors.New("request not inspected: " + err.Error())}
	}
	h := c.queue[0]
	c.queue = c.queue[1:]
	return h
}

type connKey struct{}

// ConnContext must be installed as the http.Server's ConnContext, so Filter
// can find the connection a request arrived on.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	if cc, ok := c.(*captureConn); ok {
		return context.WithValue(ctx, connKey{}, cc)
	}
	return ctx
}

// takeHeader returns the header of r and, for HTTP/1.x over TLS, the TLS
// state net/http cannot see through captureConn.
func takeHeader(r *http.Request) (*Header, *tls.ConnectionState) {
	if r.ProtoMajor >= 2 {
		return headerFromRequest(r), nil
	}
	cc, ok := r.Context().Value(connKey{}).(*captureConn)
	if !ok {
		return &Header{Err: errors.New("request not inspected: connection not captured")}, nil
	}
	h := cc.next()
	if h.Err == nil && (h.Method != r.Method || h.Target != r.RequestURI) {
		h.Err = errors.New("captured header does not match the request")
	}
	return h, cc.tls
}

// TunnelFunc takes over a connection IsTunnel matched, closing it when done.
// head is what was read from c so far.
type TunnelFunc func(c net.Conn, head []byte)

// DebugFunc logs a message with slog-style key/value pairs.
type DebugFunc func(msg string, args ...any)

// PassthroughFunc decides from a TLS ClientHello's server name whether to
// pass the connection on still encrypted: it returns the tunnel to use, or
// nil to terminate TLS here.
type PassthroughFunc func(serverName string) TunnelFunc

// maxSniff bounds the bytes read looking for a connection's first line, or
// a ping probe's header.
const maxSniff = 1024

// recordTypeHandshake is the first byte of a TLS ClientHello.
const recordTypeHandshake = 0x16

// IsTunnel is a crude test, on the start of a connection, for PageKite
// tunnel handshakes and relay probes, and proxy CONNECTs. A probe for /ping
// is only a tunnel with Host ping.pagekite, so head must hold its whole
// header (see sniff).
func IsTunnel(head []byte) bool {
	for _, p := range []string{"CONNECT ", "PING ", "GET /~:PageKite:~/", "GET /Beanstalk~Magic~Beans/"} {
		if bytes.HasPrefix(head, []byte(p)) {
			return true
		}
	}
	if !isPing(head) {
		return false
	}
	for _, line := range bytes.Split(head, []byte("\n"))[1:] {
		name, value, ok := bytes.Cut(bytes.TrimRight(line, "\r"), []byte(":"))
		if ok && bytes.EqualFold(name, []byte("Host")) {
			return bytes.EqualFold(bytes.TrimSpace(value), []byte("ping.pagekite"))
		}
	}
	return false
}

func isPing(head []byte) bool {
	return bytes.HasPrefix(head, []byte("HEAD /ping ")) || bytes.HasPrefix(head, []byte("GET /ping "))
}

// Options configures Listen. All fields but MaxHeaderBytes are optional.
type Options struct {
	// TLS, if set, makes Listen terminate TLS.
	TLS *tls.Config
	// MaxHeaderBytes should be the server's MaxHeaderBytes.
	MaxHeaderBytes int
	// Tunnel receives HTTP/1.x connections IsTunnel matches.
	Tunnel TunnelFunc
	// Passthrough is offered TLS connections by SNI, before the handshake.
	Passthrough PassthroughFunc
	// Plain receives connections to a TLS listener that are not TLS, with
	// what was read replayed; without it they are dropped.
	Plain func(net.Conn)
	// Debug is told how each connection is dispatched or why it was dropped.
	Debug DebugFunc
}

// Listen wraps ln so every HTTP/1.x connection it accepts is captured.
//
// With TLS, it also terminates TLS. net/http only treats a connection
// as TLS (setting Request.TLS and serving HTTP/2) when it is a bare
// *tls.Conn, so handshakes are done here, concurrently, and connections that
// negotiate HTTP/2 are handed over unwrapped; Filter restores Request.TLS for
// the captured ones.
//
// With Tunnel, each HTTP/1.x connection's start is read here too, and
// connections IsTunnel matches go to Tunnel instead of the server, so no
// rule ever sees them. Some PageKite handshakes lack the Host header
// net/http requires, so this cannot wait for the server.
//
// With Passthrough or Plain, a TLS listener reads each ClientHello before
// any handshake, to route connections by SNI, or to Plain if not TLS.
func Listen(ln net.Listener, o Options) net.Listener {
	debug := o.Debug
	if debug == nil {
		debug = func(string, ...any) {}
	}
	l := &listener{Listener: ln, tlsConfig: o.TLS, tunnel: o.Tunnel, passthrough: o.Passthrough, plain: o.Plain, debug: debug, maxBytes: o.MaxHeaderBytes + 4096}
	if o.TLS != nil || o.Tunnel != nil {
		l.conns = make(chan net.Conn)
		l.errs = make(chan error, 1)
		l.done = make(chan struct{})
		go l.acceptLoop()
	}
	return l
}

type listener struct {
	net.Listener
	tlsConfig   *tls.Config
	tunnel      TunnelFunc
	passthrough PassthroughFunc
	plain       func(net.Conn)
	debug       DebugFunc
	maxBytes    int

	conns     chan net.Conn
	errs      chan error
	done      chan struct{}
	closeOnce sync.Once
}

func (l *listener) Accept() (net.Conn, error) {
	if l.conns == nil {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		return &captureConn{Conn: c, maxBytes: l.maxBytes}, nil
	}
	select {
	case c := <-l.conns:
		return c, nil
	case err := <-l.errs:
		return nil, err
	}
}

func (l *listener) Close() error {
	l.closeOnce.Do(func() {
		if l.done != nil {
			close(l.done)
		}
	})
	return l.Listener.Close()
}

func (l *listener) acceptLoop() {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			l.errs <- err
			return
		}
		go l.prepare(c)
	}
}

// prepare runs the TLS handshake and tunnel check off the accept loop, so a
// slow client cannot hold up others.
func (l *listener) prepare(raw net.Conn) {
	c := raw
	remote := raw.RemoteAddr().String()
	l.debug("connection accepted", "local", raw.LocalAddr().String(), "remote", remote)
	var state *tls.ConnectionState
	if l.tlsConfig != nil && (l.passthrough != nil || l.plain != nil) {
		name, head, ok := peekServerName(raw)
		if !ok && l.plain != nil && len(head) > 0 && head[0] != recordTypeHandshake {
			l.debug("not TLS, handled as plaintext", "remote", remote, "head", printable(head))
			l.plain(&prefixConn{Conn: raw, head: head})
			return
		}
		if !ok {
			l.debug("no TLS ClientHello, dropped", "remote", remote, "bytes", len(head), "head", printable(head))
			raw.Close()
			return
		}
		if l.passthrough != nil {
			if t := l.passthrough(name); t != nil {
				l.debug("TLS passthrough", "remote", remote, "sni", name)
				t(raw, head)
				return
			}
		}
		l.debug("TLS terminating", "remote", remote, "sni", name)
		c = &prefixConn{Conn: raw, head: head}
	}
	if l.tlsConfig != nil {
		tc := tls.Server(c, l.tlsConfig)
		ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
		err := tc.HandshakeContext(ctx)
		cancel()
		if err != nil {
			l.debug("TLS handshake failed", "remote", remote, "err", err)
			tc.Close()
			return
		}
		st := tc.ConnectionState()
		l.debug("TLS handshake done", "remote", remote, "version", tls.VersionName(st.Version), "alpn", st.NegotiatedProtocol)
		if st.NegotiatedProtocol == "h2" {
			l.hand(tc)
			return
		}
		c, state = tc, &st
	}
	if l.tunnel != nil {
		head, err := sniff(c)
		if len(head) == 0 && err != nil {
			l.debug("no request line, dropped", "remote", remote, "err", err)
			c.Close()
			return
		}
		l.debug("connection start", "remote", remote, "head", printable(head), "tunnel", IsTunnel(head))
		if IsTunnel(head) {
			l.tunnel(c, head)
			return
		}
		c = &prefixConn{Conn: c, head: head}
	}
	l.hand(&captureConn{Conn: c, tls: state, maxBytes: l.maxBytes})
}

func (l *listener) hand(c net.Conn) {
	select {
	case l.conns <- c:
	case <-l.done:
		c.Close()
	}
}

// sniff reads until the first LF (or, for a ping probe, the end of the
// header), maxSniff bytes, an error or handshakeTimeout, whichever comes
// first, and returns all bytes read.
func sniff(c net.Conn) ([]byte, error) {
	c.SetReadDeadline(time.Now().Add(handshakeTimeout))
	defer c.SetReadDeadline(time.Time{})
	buf := make([]byte, 0, maxSniff)
	for len(buf) < maxSniff && !sniffed(buf) {
		n, err := c.Read(buf[len(buf):maxSniff])
		buf = buf[:len(buf)+n]
		if err != nil {
			return buf, err
		}
	}
	return buf, nil
}

func sniffed(buf []byte) bool {
	if bytes.IndexByte(buf, '\n') < 0 {
		return false
	}
	return !isPing(buf) || bytes.Contains(buf, []byte("\r\n\r\n")) || bytes.Contains(buf, []byte("\n\n"))
}

// errHelloRead stops a handshake once the ClientHello is read.
var errHelloRead = errors.New("ClientHello read")

// peekServerName reads a TLS ClientHello from c without answering it, and
// returns its server name and the bytes read, for replaying.
func peekServerName(c net.Conn) (string, []byte, bool) {
	hc := &helloConn{Conn: c}
	name, ok := "", false
	cfg := &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		name, ok = h.ServerName, true
		return nil, errHelloRead
	}}
	c.SetReadDeadline(time.Now().Add(handshakeTimeout))
	defer c.SetReadDeadline(time.Time{})
	tls.Server(hc, cfg).Handshake()
	return name, hc.buf, ok
}

// helloConn records what is read, and discards writes (the alert sent when
// the handshake is stopped).
type helloConn struct {
	net.Conn
	buf []byte
}

func (c *helloConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.buf = append(c.buf, p[:n]...)
	return n, err
}

func (c *helloConn) Write(p []byte) (int, error) { return len(p), nil }

// printable returns up to 80 bytes of b, quoted, for logging.
func printable(b []byte) string {
	if len(b) > 80 {
		b = b[:80]
	}
	return strconv.Quote(string(b))
}

// prefixConn returns head before reading from Conn.
type prefixConn struct {
	net.Conn
	head []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.head) > 0 {
		n := copy(p, c.head)
		c.head = c.head[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
