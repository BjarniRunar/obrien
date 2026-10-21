// SPDX-License-Identifier: AGPL-3.0-or-later

package trace

import (
	"slices"
	"strconv"
	"strings"
)

// xmlTok tokenizes XML a byte at a time. Each element is emitted as its
// name, its attributes (sorted, each name followed by its value's word
// tokens) and AE, or NA if it has none, its text as word tokens and its
// children, then TE; an element
// with neither text nor children ends with EE instead. Comments,
// processing instructions and declarations are skipped; entities are
// decoded only for their class.
type xmlTok struct {
	out   *[]string
	stack []xmlElem
	st    xmlState
	w     words
	k     key

	name     []byte // raw name of the tag being read
	inText   bool   // inside a run of text with a word in it
	attrs    [][]string
	attrVals []string
	quote    byte
	ent      []byte // entity being read, after '&'; nil outside one
	entInVal bool
	skip     []byte // terminator being skipped to, e.g. "-->"
	skipN    int
	bang     []byte // bytes after "<!", until the markup kind is known
	depth    int    // '[' nesting in a declaration
	cdata    int    // ']' bytes held back in CDATA
}

type xmlElem struct {
	raw   string
	empty bool // no text or children seen yet
}

type xmlState int

const (
	xText xmlState = iota
	xLt
	xName
	xAttrs
	xAttrName
	xAttrEq
	xAttrQuote
	xAttrVal
	xSelfClose
	xEndName
	xBang
	xSkip
	xDecl
	xCDATA
)

func newXML(out *[]string) *xmlTok {
	return &xmlTok{out: out}
}

// child marks the current element as having content.
func (x *xmlTok) child() {
	if len(x.stack) > 0 {
		x.stack[len(x.stack)-1].empty = false
	}
}

func isNameByte(c byte) bool {
	return !isSpace(c) && c != '/' && c != '>' && c != '=' && c != '<' && c != '"' && c != '\''
}

func (x *xmlTok) write(p []byte) bool {
	for i := 0; i < len(p); i++ {
		if !x.byte(p[i]) {
			return false
		}
	}
	return true
}

func (x *xmlTok) byte(c byte) bool {
	if x.ent != nil {
		return x.entity(c)
	}
	switch x.st {
	case xText:
		switch {
		case c == '<':
			x.endText()
			x.st = xLt
		case c == '&':
			x.ent, x.entInVal = []byte{}, false
		default:
			return x.textByte(c)
		}
	case xLt:
		switch {
		case c == '/':
			x.st, x.name = xEndName, x.name[:0]
		case c == '!':
			x.st, x.bang = xBang, x.bang[:0]
		case c == '?':
			x.skipTo("?>")
		case isNameByte(c):
			x.st, x.name, x.attrs = xName, append(x.name[:0], c), nil
		default:
			return false
		}
	case xName:
		switch {
		case isSpace(c):
			x.st = xAttrs
		case c == '/':
			x.st = xSelfClose
		case c == '>':
			x.open(false)
		case isNameByte(c):
			x.addName(c)
		default:
			return false
		}
	case xAttrs:
		switch {
		case isSpace(c):
		case c == '/':
			x.st = xSelfClose
		case c == '>':
			x.open(false)
		case isNameByte(c):
			x.st = xAttrName
			x.k.add(c)
		default:
			return false
		}
	case xAttrName:
		switch {
		case c == '=':
			x.st = xAttrQuote
		case isSpace(c):
			x.st = xAttrEq
		case isNameByte(c):
			x.k.add(c)
		default:
			return false
		}
	case xAttrEq:
		switch {
		case isSpace(c):
		case c == '=':
			x.st = xAttrQuote
		default:
			return false
		}
	case xAttrQuote:
		switch {
		case isSpace(c):
		case c == '"' || c == '\'':
			x.st, x.quote, x.attrVals = xAttrVal, c, nil
			x.w.out = &x.attrVals
		default:
			return false
		}
	case xAttrVal:
		switch c {
		case x.quote:
			x.w.end()
			x.attrs = append(x.attrs, append([]string{x.k.take()}, x.attrVals...))
			x.st = xAttrs
		case '<':
			return false
		case '&':
			x.ent, x.entInVal = []byte{}, true
		default:
			x.w.add(c)
		}
	case xSelfClose:
		if c != '>' {
			return false
		}
		x.open(true)
	case xEndName:
		switch {
		case c == '>':
			if len(x.stack) == 0 || x.stack[len(x.stack)-1].raw != strings.TrimSpace(string(x.name)) {
				return false
			}
			end := "TE"
			if x.stack[len(x.stack)-1].empty {
				end = "EE"
			}
			*x.out = append(*x.out, end)
			x.stack = x.stack[:len(x.stack)-1]
			x.st = xText
		default:
			x.addName(c)
		}
	case xBang:
		return x.bangByte(c)
	case xSkip:
		if c == x.skip[x.skipN] {
			if x.skipN++; x.skipN == len(x.skip) {
				x.st = xText
			}
		} else {
			x.skipN = 0
			if c == x.skip[0] {
				x.skipN = 1
			}
		}
	case xDecl:
		switch c {
		case '[':
			x.depth++
		case ']':
			x.depth--
		case '>':
			if x.depth <= 0 {
				x.st = xText
			}
		}
	case xCDATA:
		return x.cdataByte(c)
	}
	return true
}

// bangByte reads what follows "<!" until it is known to be a comment, a
// CDATA section or a declaration.
func (x *xmlTok) bangByte(c byte) bool {
	x.bang = append(x.bang, c)
	b := string(x.bang)
	switch {
	case b == "--":
		x.skipTo("-->")
	case b == "[CDATA[":
		x.st, x.cdata = xCDATA, 0
	case strings.HasPrefix("--", b) || strings.HasPrefix("[CDATA[", b):
	default:
		x.st, x.depth = xDecl, 0
		return x.byte(c)
	}
	return true
}

// maxName caps the raw tag names kept to match end tags against.
const maxName = 256

func (x *xmlTok) addName(c byte) {
	if len(x.name) < maxName {
		x.name = append(x.name, c)
	}
}

func (x *xmlTok) skipTo(end string) {
	x.st, x.skip, x.skipN = xSkip, []byte(end), 0
}

// cdataByte treats CDATA content as text, holding back ']' bytes that may
// start the "]]>" terminator.
func (x *xmlTok) cdataByte(c byte) bool {
	switch {
	case c == ']':
		x.cdata++
		return true
	case c == '>' && x.cdata >= 2:
		for ; x.cdata > 2; x.cdata-- {
			x.textByte(']')
		}
		x.cdata = 0
		x.st = xText
		return true
	}
	for ; x.cdata > 0; x.cdata-- {
		if !x.textByte(']') {
			return false
		}
	}
	return x.textByte(c)
}

func (x *xmlTok) textByte(c byte) bool {
	if !x.inText {
		if isSpace(c) {
			return true
		}
		if len(x.stack) == 0 {
			return false
		}
		x.child()
		x.w.out, x.inText = x.out, true
	}
	x.w.add(c)
	return true
}

func (x *xmlTok) endText() {
	if x.inText {
		x.w.flush()
		x.w.some, x.inText = false, false
	}
}

func (x *xmlTok) open(selfClose bool) {
	raw := string(x.name)
	var k key
	for i := 0; i < len(raw); i++ {
		k.add(raw[i])
	}
	x.child()
	*x.out = append(*x.out, k.take())
	slices.SortStableFunc(x.attrs, func(a, b []string) int {
		if c := strings.Compare(a[0], b[0]); c != 0 {
			return c
		}
		return slices.Compare(a[1:], b[1:])
	})
	for _, a := range x.attrs {
		*x.out = append(*x.out, a...)
	}
	if len(x.attrs) > 0 {
		*x.out = append(*x.out, "AE")
	} else {
		*x.out = append(*x.out, "NA")
	}
	x.attrs = nil
	if selfClose {
		*x.out = append(*x.out, "EE")
	} else {
		x.stack = append(x.stack, xmlElem{raw: raw, empty: true})
	}
	x.st = xText
}

var xmlEntities = map[string]byte{"lt": '<', "gt": '>', "amp": '&', "quot": '"', "apos": '\''}

// entity reads an entity reference after '&'. Known and numeric entities
// count as the character they stand for. Anything else counts as its own
// text, and the byte that ended it is read again.
func (x *xmlTok) entity(c byte) bool {
	if c != ';' && len(x.ent) < 12 && (class(c) == 'A' || c == '#') {
		x.ent = append(x.ent, c)
		return true
	}
	name := string(x.ent)
	x.ent = nil
	var bytes []byte
	decoded := c == ';'
	if b, ok := xmlEntities[name]; ok && decoded {
		bytes = []byte{b}
	} else if r, ok := charRef(name); ok && decoded {
		bytes = []byte(string(r))
	} else {
		bytes, decoded = append([]byte{'&'}, name...), false
	}
	for _, b := range bytes {
		if x.entInVal {
			x.w.add(b)
		} else if !x.textByte(b) {
			return false
		}
	}
	if decoded {
		return true
	}
	return x.byte(c)
}

func charRef(name string) (rune, bool) {
	if !strings.HasPrefix(name, "#") {
		return 0, false
	}
	var n uint64
	var err error
	if strings.HasPrefix(name, "#x") {
		n, err = strconv.ParseUint(name[2:], 16, 32)
	} else {
		n, err = strconv.ParseUint(name[1:], 10, 32)
	}
	return rune(n), err == nil
}

func (x *xmlTok) end() bool {
	x.endText()
	return len(x.stack) == 0 && x.st == xText && x.ent == nil
}
