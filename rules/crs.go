// SPDX-License-Identifier: AGPL-3.0-or-later

package rules

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/corazawaf/coraza-coreruleset/crs/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
)

//go:embed crs.conf
var crsBase string

// CRSBodyLimit is the default CRSConfig.BodyLimit.
const CRSBodyLimit = 1 << 20

// Error types reported to CRSConfig.OnError.
const (
	CRSErrBodyRead      = "body_read"      // reading the request body failed
	CRSErrBodyBuffer    = "body_buffer"    // reading back Coraza's body buffer failed
	CRSErrBodyTruncated = "body_truncated" // body over BodyLimit, inspected only in part
	CRSErrProcess       = "process"        // Coraza failed to process the body
	CRSErrClose         = "close"          // closing the transaction failed
	CRSErrBodyParse     = "body_parse"     // rule 200002: body did not parse
	CRSErrMultipart     = "multipart"      // rule 200003: multipart failed strict checks
	CRSErrArgsLimit     = "args_limit"     // rules 200004, 200005: too many arguments
	CRSErrURIParse      = "uri_parse"      // rule 200009: URI did not parse
)

// crsErrRules maps the engine rules in crs.conf that flag malformed requests
// to their error types.
var crsErrRules = map[int]string{
	200002: CRSErrBodyParse,
	200003: CRSErrMultipart,
	200004: CRSErrArgsLimit,
	200005: CRSErrArgsLimit,
	200009: CRSErrURIParse,
}

// CRSErrorFunc is called for each error met while checking a request, with
// its type (one of the CRSErr constants).
type CRSErrorFunc func(r *http.Request, kind string, err error)

// CRSConfig configures the OWASP Core Rule Set.
type CRSConfig struct {
	// Block rejects requests the CRS interrupts; otherwise they are only
	// reported to OnDetect and passed on.
	Block bool
	// Paranoia is the CRS blocking paranoia level, 1-4.
	Paranoia int
	// BodyLimit is how much of a request body is inspected, CRSBodyLimit if
	// 0. It is also the in-memory limit, so bodies are never buffered to disk.
	BodyLimit int
	// Directives, if not empty, are loaded after the CRS setup and before
	// its rules, for tuning and exclusions.
	Directives string
	// OnMatch is called for every logged CRS rule that matched a request,
	// with the name "crs-<id>".
	OnMatch MatchFunc
	// OnDetect is called, when Block is off, for each request the CRS would
	// have rejected.
	OnDetect RejectFunc
	// OnTime is called for each request with the time the CRS took,
	// including reading the body.
	OnTime TimeFunc
	// OnError is called for each error met while checking a request.
	OnError CRSErrorFunc
}

// CRSError is the error CRS rejects a request with: the CRS rules it
// matched, or an error other than CRSErrBodyTruncated.
type CRSError struct{ Err error }

func (e CRSError) Error() string { return "crs: " + e.Err.Error() }
func (e CRSError) Unwrap() error { return e.Err }

// CRS is a Rule running the OWASP Core Rule Set with Coraza. It reads up to
// BodyLimit of the request body, and replaces
// Request.Body so the handler still receives all of it.
type CRS struct {
	cfg CRSConfig
	waf coraza.WAF
}

// NewCRS compiles the rule set. Invalid Directives are an error.
func NewCRS(cfg CRSConfig) (*CRS, error) {
	if cfg.Paranoia < 1 || cfg.Paranoia > 4 {
		return nil, fmt.Errorf("paranoia level %d: must be 1-4", cfg.Paranoia)
	}
	if cfg.BodyLimit == 0 {
		cfg.BodyLimit = CRSBodyLimit
	}
	conf := coraza.NewWAFConfig().
		WithRootFS(crs.FS).
		WithDirectives(crsBase).
		WithDirectives(fmt.Sprintf("SecRequestBodyLimit %d\nSecRequestBodyInMemoryLimit %d", cfg.BodyLimit, cfg.BodyLimit)).
		WithDirectives("Include @crs-setup.conf.example").
		WithDirectives(fmt.Sprintf(`SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d"`, cfg.Paranoia))
	if cfg.Directives != "" {
		conf = conf.WithDirectives(cfg.Directives)
	}
	waf, err := coraza.NewWAF(conf.WithDirectives("Include @owasp_crs/*.conf"))
	if err != nil {
		return nil, err
	}
	return &CRS{cfg: cfg, waf: waf}, nil
}

func (c *CRS) Check(r *http.Request) error {
	start := time.Now()
	tx := c.waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		if err := tx.Close(); err != nil {
			c.onError(r, CRSErrClose, err)
		}
		if c.cfg.OnTime != nil {
			c.cfg.OnTime(r, time.Since(start))
		}
	}()

	in, kind, err := c.process(tx, r)
	if err != nil {
		c.onError(r, kind, err)
		if kind != CRSErrBodyTruncated {
			return CRSError{err}
		}
	}
	var ids []string
	for _, m := range tx.MatchedRules() {
		if !logged(m) {
			continue
		}
		if kind, ok := crsErrRules[m.Rule().ID()]; ok {
			c.onError(r, kind, errors.New(m.Message()))
		}
		id := fmt.Sprint(m.Rule().ID())
		ids = append(ids, id+" "+m.Message())
		if c.cfg.OnMatch != nil {
			c.cfg.OnMatch(r, "crs-"+id)
		}
	}
	if in == nil {
		return nil
	}
	rej := CRSError{errors.New(strings.Join(ids, "; "))}
	if !c.cfg.Block {
		if c.cfg.OnDetect != nil {
			c.cfg.OnDetect(r, rej)
		}
		return nil
	}
	return Rejection{Err: rej}
}

func (c *CRS) onError(r *http.Request, kind string, err error) {
	if c.cfg.OnError != nil {
		c.cfg.OnError(r, kind, err)
	}
}

// process runs the transaction. A returned error comes with its type; only
// CRSErrBodyTruncated leaves the request checked, as far as it was read.
func (c *CRS) process(tx types.Transaction, r *http.Request) (*types.Interruption, string, error) {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		tx.ProcessConnection(ap.Addr().Unmap().String(), int(ap.Port()), "", 0)
	}
	tx.ProcessURI(r.RequestURI, r.Method, r.Proto)
	tx.AddRequestHeader("Host", r.Host)
	tx.SetServerName(r.Host)
	for name, values := range r.Header {
		for _, v := range values {
			tx.AddRequestHeader(name, v)
		}
	}
	for _, te := range r.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", te)
	}
	if in := tx.ProcessRequestHeaders(); in != nil {
		return in, "", nil
	}
	if r.Body != nil && r.Body != http.NoBody && tx.IsRequestBodyAccessible() {
		in, _, err := tx.ReadRequestBodyFrom(r.Body)
		if err != nil {
			return nil, CRSErrBodyRead, fmt.Errorf("read body: %w", err)
		}
		// The transaction's buffer is released by Close, before the
		// handler runs, so what was read is copied out.
		rbr, err := tx.RequestBodyReader()
		if err != nil {
			return nil, CRSErrBodyBuffer, fmt.Errorf("body buffer: %w", err)
		}
		read, err := io.ReadAll(rbr)
		if err != nil {
			return nil, CRSErrBodyBuffer, fmt.Errorf("body buffer: %w", err)
		}
		// Coraza does not report whether it stopped at the limit, so a
		// body that filled it is probed for one more byte.
		var more []byte
		if len(read) >= c.cfg.BodyLimit {
			var b [1]byte
			if n, _ := io.ReadFull(r.Body, b[:]); n > 0 {
				more = b[:n]
			}
		}
		r.Body = prefixedBody{io.MultiReader(bytes.NewReader(read), bytes.NewReader(more), r.Body), r.Body}
		if in != nil {
			return in, "", nil
		}
		if len(more) > 0 {
			in, err := tx.ProcessRequestBody()
			if err != nil {
				return nil, CRSErrProcess, err
			}
			return in, CRSErrBodyTruncated, fmt.Errorf("body over %d bytes, inspected in part", c.cfg.BodyLimit)
		}
	}
	in, err := tx.ProcessRequestBody()
	if err != nil {
		return nil, CRSErrProcess, err
	}
	return in, "", nil
}

// logged reports whether a matched rule is one to report, leaving out
// nolog rules such as CRS initialisation. Coraza's matched rules have a
// Log method that is not yet part of types.MatchedRule.
func logged(m types.MatchedRule) bool {
	if l, ok := m.(interface{ Log() bool }); ok {
		return l.Log()
	}
	return m.Message() != ""
}

type prefixedBody struct {
	io.Reader
	io.Closer
}

// Close releases the compiled rules, where Coraza supports it.
func (c *CRS) Close() error {
	if closer, ok := c.waf.(experimental.WAFCloser); ok {
		return closer.Close()
	}
	return nil
}
