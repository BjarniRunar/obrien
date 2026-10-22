// SPDX-License-Identifier: AGPL-3.0-or-later

package trace

import (
	"bytes"
	"mime"
	"strconv"
	"strings"
)

// multipartTok tokenizes a multipart body a byte at a time. Each part is
// emitted as PART, HS and its header size bucket, its field name if it has
// one, FILE and the word tokens of its file name if it has one, and its
// contents as a file. Parts after maxParts are only counted, and MORE
// stands for all of them.
type multipartTok struct {
	out   *[]string
	delim []byte // "\r\n--" + boundary
	fail  []int  // KMP failure function of delim
	st    mpState
	m     int    // bytes of delim matched
	tail  []byte // bytes after a delimiter, before its line ends
	hdr   []byte
	parts int
	file  *fileTok // contents of the current part; nil outside one
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

// maxParts caps the parts traced, which bounds a trace's size since each
// file's tokens are bounded.
const maxParts = 16

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
		prev := m.m
		for m.m >= 0 && m.delim[m.m] != c {
			m.m = m.fail[m.m]
		}
		m.m++
		// The bytes held as a possible delimiter were delim[:prev] and c;
		// those no longer matched are part content.
		if rel := prev + 1 - m.m; m.file != nil && rel > prev {
			m.file.write(m.delim[:prev])
			m.file.write([]byte{c})
		} else if m.file != nil && rel > 0 {
			m.file.write(m.delim[:rel])
		}
		if m.m == len(m.delim) {
			if m.file != nil {
				m.file.end(true)
				m.file = nil
			}
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
	if m.parts++; m.parts > maxParts {
		if m.parts == maxParts+1 {
			*m.out = append(*m.out, "MORE")
		}
		return
	}
	*m.out = append(*m.out, "PART", "HS"+strconv.Itoa((len(hdr)+15)/16))
	var disp, ctype bool
	kind := ""
	for _, line := range bytes.Split(hdr, []byte("\r\n")) {
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		switch strings.ToLower(string(bytes.TrimSpace(name))) {
		case "content-disposition":
			if disp {
				continue
			}
			disp = true
			if _, params, err := mime.ParseMediaType(string(value)); err == nil {
				if n, ok := params["name"]; ok {
					*m.out = append(*m.out, keyOf(n))
				}
				if n, ok := params["filename"]; ok {
					*m.out = append(*m.out, "FILE")
					*m.out = append(*m.out, wordsOf(n)...)
				}
			}
		case "content-type":
			if !ctype {
				ctype = true
				mt, _, _ := mime.ParseMediaType(string(value))
				kind = structured(mt)
			}
		}
	}
	m.file = newFile(m.out, kind)
}

// end cuts short a part the body ended in.
func (m *multipartTok) end(bool) bool {
	if m.file != nil {
		m.file.end(false)
		m.file = nil
	}
	return m.st == mpDone
}
