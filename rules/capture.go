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

// Listen wraps ln so every HTTP/1.x connection it accepts is captured.
// maxHeaderBytes should be the server's MaxHeaderBytes.
//
// With tlsConfig, it also terminates TLS. net/http only treats a connection
// as TLS (setting Request.TLS and serving HTTP/2) when it is a bare
// *tls.Conn, so handshakes are done here, concurrently, and connections that
// negotiate HTTP/2 are handed over unwrapped; Filter restores Request.TLS for
// the captured ones.
func Listen(ln net.Listener, tlsConfig *tls.Config, maxHeaderBytes int) net.Listener {
	l := &listener{Listener: ln, tlsConfig: tlsConfig, maxBytes: maxHeaderBytes + 4096}
	if tlsConfig != nil {
		l.conns = make(chan net.Conn)
		l.errs = make(chan error, 1)
		l.done = make(chan struct{})
		go l.acceptTLS()
	}
	return l
}

type listener struct {
	net.Listener
	tlsConfig *tls.Config
	maxBytes  int

	conns     chan net.Conn
	errs      chan error
	done      chan struct{}
	closeOnce sync.Once
}

func (l *listener) Accept() (net.Conn, error) {
	if l.tlsConfig == nil {
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

func (l *listener) acceptTLS() {
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
		go l.handshake(c)
	}
}

func (l *listener) handshake(raw net.Conn) {
	tc := tls.Server(raw, l.tlsConfig)
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	err := tc.HandshakeContext(ctx)
	cancel()
	if err != nil {
		tc.Close()
		return
	}
	var c net.Conn = tc
	state := tc.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		c = &captureConn{Conn: tc, tls: &state, maxBytes: l.maxBytes}
	}
	select {
	case l.conns <- c:
	case <-l.done:
		c.Close()
	}
}
