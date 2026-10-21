// SPDX-License-Identifier: AGPL-3.0-or-later

package trace

import (
	"bytes"
	"mime"
	"strconv"
)

// multipartTok tokenizes a multipart body a byte at a time. Each part is
// emitted as PART, HS and its header size bucket, and its field name if it
// has one. Part contents are skipped without being buffered.
type multipartTok struct {
	out   *[]string
	delim []byte // "\r\n--" + boundary
	fail  []int  // KMP failure function of delim
	st    mpState
	m     int    // bytes of delim matched
	tail  []byte // bytes after a delimiter, before its line ends
	hdr   []byte
}

type mpState int

const (
	mpSeek mpState = iota // looking for a delimiter
	mpAfterDelim
	mpHeaders
	mpDone
)

// maxPartHeader caps a part's header block.
const maxPartHeader = 16 << 10

func newMultipart(out *[]string, boundary string) *multipartTok {
	d := []byte("\r\n--" + boundary)
	f := make([]int, len(d)+1)
	f[0] = -1
	for i, k := 1, -1; i <= len(d); i++ {
		for k >= 0 && d[k] != d[i-1] {
			k = f[k]
		}
		k++
		f[i] = k
	}
	m := &multipartTok{out: out, delim: d, fail: f}
	// The first delimiter may start the body, without a CRLF before it.
	m.m = 2
	return m
}

func (m *multipartTok) write(p []byte) bool {
	for _, c := range p {
		if !m.byte(c) {
			return false
		}
	}
	return true
}

func (m *multipartTok) byte(c byte) bool {
	switch m.st {
	case mpSeek:
		for m.m >= 0 && m.delim[m.m] != c {
			m.m = m.fail[m.m]
		}
		if m.m++; m.m == len(m.delim) {
			m.st, m.tail, m.m = mpAfterDelim, m.tail[:0], 0
		}
	case mpAfterDelim:
		m.tail = append(m.tail, c)
		switch t := string(m.tail); {
		case t == "--":
			m.st = mpDone
		case t == "-":
		case bytes.HasSuffix(m.tail, []byte("\r\n")):
			if len(bytes.Trim(m.tail[:len(m.tail)-2], " \t")) != 0 {
				return false
			}
			m.st, m.hdr = mpHeaders, m.hdr[:0]
		case c != ' ' && c != '\t' && c != '\r':
			return false
		}
	case mpHeaders:
		m.hdr = append(m.hdr, c)
		if len(m.hdr) > maxPartHeader {
			return false
		}
		if string(m.hdr) == "\r\n" || bytes.HasSuffix(m.hdr, []byte("\r\n\r\n")) {
			m.part(m.hdr[:len(m.hdr)-2])
			m.st = mpSeek
		}
	}
	return true
}

func (m *multipartTok) part(hdr []byte) {
	*m.out = append(*m.out, "PART", "HS"+strconv.Itoa((len(hdr)+15)/16))
	for _, line := range bytes.Split(hdr, []byte("\r\n")) {
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok || !bytes.EqualFold(bytes.TrimSpace(name), []byte("Content-Disposition")) {
			continue
		}
		if _, params, err := mime.ParseMediaType(string(value)); err == nil {
			if n, ok := params["name"]; ok {
				*m.out = append(*m.out, keyOf(n))
			}
		}
		return
	}
}

func (m *multipartTok) end() bool {
	return m.st == mpDone
}
