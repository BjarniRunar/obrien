// SPDX-License-Identifier: AGPL-3.0-or-later

package trace

// jsonTok tokenizes JSON a byte at a time. Each key is emitted before its
// value, each string or number as its word tokens, and the end of each
// object or array as OE or LE; an empty object or array is EO or EL
// instead. Several top-level values in a row are accepted.
type jsonTok struct {
	out   *[]string
	stack []jsonFrame
	st    jsonState
	w     words
	k     key

	inKey bool   // the string being read is a key
	esc   int    // 0, or bytes of a \ escape read so far
	hex   rune   // \u escape value being read
	lit   string // literal being read ("true", ...)
	litN  int
	surr  bool // the last \u escape was a high surrogate
}

type jsonFrame struct {
	obj bool
}

type jsonState int

const (
	jValue jsonState = iota
	jValueOrClose
	jKeyOrClose
	jKey
	jColon
	jAfter
	jString
	jNumber
	jLiteral
)

func newJSON(out *[]string) *jsonTok {
	j := &jsonTok{out: out}
	j.w.out = out
	return j
}

// write returns false once the input is not valid JSON.
func (j *jsonTok) write(p []byte) bool {
	for i := 0; i < len(p); i++ {
		if !j.byte(p[i]) {
			return false
		}
	}
	return true
}

func (j *jsonTok) byte(c byte) bool {
	switch j.st {
	case jString:
		return j.stringByte(c)
	case jNumber:
		if c >= '0' && c <= '9' || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E' {
			j.w.add(c)
			return true
		}
		j.w.end()
		j.st = jAfter
		return j.byte(c)
	case jLiteral:
		if c != j.lit[j.litN] {
			return false
		}
		if j.litN++; j.litN == len(j.lit) {
			*j.out = append(*j.out, upper(j.lit))
			j.st = jAfter
		}
		return true
	}
	if isSpace(c) {
		return true
	}
	switch j.st {
	case jValueOrClose:
		if c == ']' {
			return j.close(false, true)
		}
		fallthrough
	case jValue:
		return j.value(c)
	case jKeyOrClose:
		if c == '}' {
			return j.close(true, true)
		}
		fallthrough
	case jKey:
		if c != '"' {
			return false
		}
		j.st, j.inKey = jString, true
		return true
	case jColon:
		if c != ':' {
			return false
		}
		j.st = jValue
		return true
	case jAfter:
		if len(j.stack) == 0 {
			return j.value(c)
		}
		top := j.stack[len(j.stack)-1]
		switch {
		case c == ',' && top.obj:
			j.st = jKey
		case c == ',':
			j.st = jValue
		case c == '}' || c == ']':
			return j.close(c == '}', false)
		default:
			return false
		}
		return true
	}
	return false
}

func (j *jsonTok) value(c byte) bool {
	switch {
	case c == '{' || c == '[':
		j.stack = append(j.stack, jsonFrame{obj: c == '{'})
		j.st = jValueOrClose
		if c == '{' {
			j.st = jKeyOrClose
		}
	case c == '"':
		j.st, j.inKey = jString, false
	case c == '-' || c >= '0' && c <= '9':
		j.st = jNumber
		j.w.add(c)
	case c == 't' || c == 'f' || c == 'n':
		j.lit = map[byte]string{'t': "true", 'f': "false", 'n': "null"}[c]
		j.st, j.litN = jLiteral, 1
	default:
		return false
	}
	return true
}

// close ends the innermost container, which is empty if it closed straight
// after opening.
func (j *jsonTok) close(obj, empty bool) bool {
	if len(j.stack) == 0 || j.stack[len(j.stack)-1].obj != obj {
		return false
	}
	j.stack = j.stack[:len(j.stack)-1]
	var t string
	switch {
	case obj && empty:
		t = "EO"
	case empty:
		t = "EL"
	case obj:
		t = "OE"
	default:
		t = "LE"
	}
	*j.out = append(*j.out, t)
	j.st = jAfter
	return true
}

func (j *jsonTok) stringByte(c byte) bool {
	switch {
	case j.esc == 1:
		j.esc = 0
		switch c {
		case 'n':
			j.strByte('\n')
		case 't':
			j.strByte('\t')
		case 'r':
			j.strByte('\r')
		case 'b':
			j.strByte('\b')
		case 'f':
			j.strByte('\f')
		case '"', '\\', '/':
			j.strByte(c)
		case 'u':
			j.esc, j.hex = 2, 0
		default:
			return false
		}
		return true
	case j.esc >= 2:
		d, ok := unhex(c)
		if !ok {
			return false
		}
		j.hex = j.hex<<4 | rune(d)
		if j.esc++; j.esc == 6 {
			j.esc = 0
			j.codepoint(j.hex)
		}
		return true
	case c == '\\':
		j.esc = 1
		return true
	case c == '"':
		if j.inKey {
			*j.out = append(*j.out, j.k.take())
			j.st = jColon
		} else {
			j.w.end()
			j.st = jAfter
		}
		return true
	}
	j.strByte(c)
	return true
}

func (j *jsonTok) strByte(c byte) {
	if j.inKey {
		j.k.add(c)
	} else {
		j.w.add(c)
	}
}

// codepoint feeds an escaped character as the bytes of its UTF-8 encoding,
// which only matter for their class and count. A surrogate pair counts as
// one 4-byte character.
func (j *jsonTok) codepoint(r rune) {
	n := 0
	switch {
	case r < 0x80:
		j.strByte(byte(r))
		j.surr = false
		return
	case r < 0x800:
		n = 2
	case r >= 0xd800 && r < 0xdc00:
		n = 4
	case r >= 0xdc00 && r < 0xe000 && j.surr:
		n = 0
	default:
		n = 3
	}
	j.surr = r >= 0xd800 && r < 0xdc00
	for range n {
		j.strByte(0x80)
	}
}

// end returns false if the input stopped inside a value.
func (j *jsonTok) end() bool {
	if j.st == jNumber {
		j.w.end()
		j.st = jAfter
	}
	return len(j.stack) == 0 && (j.st == jAfter || j.st == jValue)
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}
