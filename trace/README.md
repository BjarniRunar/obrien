# trace/

Reduces each request to a line of tokens giving its shape, not its content.
Shown in `obrien requests` and the `--trace-log` file for 2xx/3xx/4xx
responses; meant to be mined later for patterns of expected traffic.

- `trace.go`: `Of` builds a trace from the `rules.Header` the rules judged
  and the `Body`.
- `body.go`: `Body` wraps `Request.Body`, tokenizing it as the proxy
  streams it. Picks a tokenizer by Content-Type; safe to trace while the
  transport still reads.
- `file.go`: tokenizer for one file (a body or a multipart part): sniffs
  the type, parses JSON/XML up to 20 KiB, repairs cut-off files, summarises
  the rest by type and size.
- `json.go`, `xml.go`, `form.go`, `multipart.go`: byte-at-a-time
  tokenizers. `form.go` also does query strings; `json.go` also sorts keys.
- `word.go`: word tokens, key normalisation, percent-decoding.
- `trace_test.go`: golden tests over `testdata/requests/` (traced whole and
  byte by byte, which must agree), unit tests, and a trace through
  `rules.Listen`/`rules.Filter`. `go test ./trace -update` rewrites the
  golden files; review the diff.
- `testdata/requests/`: raw HTTP/1.1 requests, stored byte for byte
  (`testdata/.gitattributes`), named for what they cover. Expected traces
  are in `testdata/traces/`.

## Syntax

Space-separated tokens, meant to become readable regexes, so no
punctuation: generated tokens are UPPERCASE, anything from the request
(keys, names, MIME type, host) is lowercase.

| Token | Meaning |
|---|---|
| `A1` `P2` `B0` | Word: class and length bucket |
| `REST-A3` | Rest of a value after 10 words: class and size bucket |
| `page` `order` | Key or XML name, followed by its value's tokens |
| `GET` `POST` … | Method |
| `HC1` | Header field count / 16, rounded up |
| `MIME application_json` | Media type of `Content-Type` |
| `HOST example_com_8080` | Host |
| `HEADERS` | Selected headers follow |
| `BODY` | Body follows |
| `JSON` `XML` `FORM` `MULTIPART` `OTHER` | Kind of a body or file |
| `SZ4` | Size of an `OTHER` file: hex digits in its length |
| `TRUE` `FALSE` `NULL` | JSON literals |
| `OE` `LE` / `EO` `EL` | End of a JSON object/list / empty object/list |
| `AE` / `NA` | End of XML attributes / element without attributes |
| `TE` / `EE` | End of XML element / of one without text or children |
| `PART HS3` | Multipart part, header size bucket |
| `FILE` | Part's file name follows, as words |
| `MORE` | Parts after 16, or form/query pairs after 64, omitted |
| `TRUNC` | File cut short (20 KiB limit or body ended) |
| `INVALID` | File is not valid JSON/XML; replaces its tokens |
| `CLOK` `CLBAD` | `Content-Length` matched the body, or not |
| `ERR` | Body framing broken; nothing follows |

Order: method, path, query, `HC`, `MIME`, `HOST`, `HEADERS`, `BODY`,
`CLOK`/`CLBAD`. `MIME`, `HOST` and `HEADERS` are omitted when absent;
`BODY` when no body bytes were read (e.g. rejected requests).

### Words

Values split on whitespace; each piece is a class and its length / 16,
rounded up (1-16 bytes is 1). An empty value is `B0`. Classes: `A` ASCII
alphanumeric, `P` printable ASCII, `B` anything else.

After 10 words, the rest of the value is one `REST-` token: the widest
class of its non-space bytes and the hex digits in its length (first to
last non-space byte); `REST-P3` is 256 B–4 KiB. Applies to every value:
path segments, query, form and header values, file names, JSON strings,
XML attribute values and XML text runs.

Path, query and form values are percent-decoded (`+` is space in query and
form; bad escapes kept). JSON escapes and XML entities are decoded.

### Keys

Lowercased; each run outside `[a-z0-9_]` becomes `_` (`vnd.api+json` →
`vnd_api_json`, `tags[]` → `tags_`); empty is `_`; cut at 64 bytes. MIME
type and host are normalised the same way.

### Parts

- **Path**: one word per segment; `/` is `B0`. Absolute-form targets use
  their path; `*` is one segment.
- **Query**: pairs split on `&`, sorted by key then value tokens; a key
  without `=` has value `B0`. First 64 pairs only, then `MORE`.
- **Headers**: `authorization`, `proxy_authorization`, `cookie`,
  `content_type`, `origin`, `access_control_request_method` and
  `access_control_request_headers`, each key with its value's words,
  sorted as the query, duplicates kept. `cookie` has no value.
- **Body**: `FORM` (`application/x-www-form-urlencoded`) as the query;
  `MULTIPART` (`multipart/*`) as parts; anything else is one file.
- **Multipart part**: `PART HSn`, the `Content-Disposition` name, `FILE`
  and the file name's words if any, then the contents as a file. First 16
  parts only, then `MORE`.
- **File kind**: `JSON` for `application/json`/`*+json`, `XML` for
  `application/xml`/`text/xml`/`*+xml`. Otherwise sniffed: `{` or `[`
  first (after whitespace) is `JSON`, `<` is `XML` unless HTML, else
  `OTHER`.
- **JSON/XML files**: first 20 KiB only. If cut short, unfinished values,
  keys, words, tags and entities are dropped, open containers closed, and
  `TRUNC` appended. Still unparseable: `INVALID`.
- **JSON**: keys precede values; strings and numbers as words; literals as
  `TRUE`/`FALSE`/`NULL`; no start markers. Object members are sorted by key
  then value tokens; lists keep order. `{"b":[],"a":{"c":1}}` is
  `a c A1 OE b EL OE`.
- **XML**: in document order. Element name, sorted attributes (name then
  value words) and `AE`, or `NA`; then text and children, then `TE`, or
  `EE` if neither (whitespace ignored). Prefixes kept (`soap:Body` →
  `soap_body`). Comments, PIs and declarations skipped; CDATA is text.
  `<p lang="en">Hi <b>there</b></p>` is `p lang A1 AE A1 b NA A1 TE TE`.
- **OTHER**: media type sniffed from the first 512 bytes as `net/http`
  does, then `SZ` of the full length (`SZ3` ≤ 4 KiB, `SZ5` ≤ 1 MiB).
- `ERR` follows whatever was traced when the framing broke (multipart
  without boundary or end).
- `CLOK`/`CLBAD` only with `Content-Length`, once the body ended.

### Examples

```
GET /blog/2026/10/my-post.html
GET A1 A1 A1 P1 HC1 HOST example_com

GET /search?q=hello&page=2
GET A1 page A1 q A1 HC1 HOST example_com

CORS preflight:
OPTIONS A1 A1 HC1 HOST example_com HEADERS access_control_request_headers P1 P1 access_control_request_method A1 origin P2

JSON:
PUT A1 A1 A1 HC1 MIME application_json HOST example_com HEADERS content_type P1 BODY JSON meta EO order id P3 items qty A1 sku A1 OE note B0 qty A1 sku A1 OE LE total P1 OE tags A1 A1 LE OE CLOK

XML:
POST A1 A1 HC1 MIME application_xml HOST example_com HEADERS content_type P1 BODY XML feed lang A1 AE title NA A1 TE entry id A1 AE title NA A1 TE body NA A1 P1 TE TE entry id A1 AE EE TE CLOK

Multipart upload:
POST A1 HC1 MIME multipart_form_data HOST example_com HEADERS content_type P2 P3 BODY MULTIPART PART HS3 title OTHER text_plain SZ1 PART HS6 photo FILE P1 OTHER image_jpeg SZ3 PART HS3 tags_ OTHER text_plain SZ1 CLOK
```
