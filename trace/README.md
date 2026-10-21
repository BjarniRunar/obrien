# trace/

Request traces: each request reduced to a line of tokens describing its
shape (path, query, selected headers, body structure) without its exact
content. Traces are shown in the request log (`obrien requests`) for
requests answered with a 2xx or 3xx status, and are
meant to be analysed later into patterns describing a site's expected
traffic. Background: [`../issues/request-fingerprinting.md`](../issues/request-fingerprinting.md).

- `trace.go`: `Of`, which builds a trace from the `rules.Header` the rules
  judged and the request's `Body`: the request line, header count, MIME
  type, host and selected headers, then the body tokens.
- `body.go`: `Body`, a request body wrapper that tokenizes the body as the
  proxy streams it to the upstream, so nothing is buffered and there is no
  size limit. It picks a tokenizer from the Content-Type, and is safe to
  trace while the transport is still reading.
- `json.go`, `xml.go`, `form.go`, `multipart.go`: streaming tokenizers for
  each body type, fed a byte at a time; `form.go` also handles query
  strings.
- `word.go`: word tokens, key normalisation and percent-decoding.
- `trace_test.go`: golden-file tests over `testdata/requests/` (each
  traced all at once and a byte at a time, which must agree), the
  tokenizers' building blocks, and a request traced through
  `rules.Listen` and `rules.Filter` as the daemon does it. Run
  `go test ./trace -update` to rewrite the golden files, then review the
  changes.
- `testdata/requests/`: synthetic raw HTTP/1.1 requests, one per file,
  stored byte for byte (see `testdata/.gitattributes`); the name says what
  each one covers. `testdata/traces/` holds the expected trace of each.

## Syntax

A trace is tokens separated by single spaces. Traces will be turned into
regular expressions that humans should be able to read, so the syntax
avoids punctuation: everything obrien generates is UPPERCASE, and
everything taken from the request (keys, names, the MIME type, the host) is
lowercase. In any position, a lowercase word is a key or a value from the
request.

| Token | Meaning |
|---|---|
| `A1` `P2` `B0` | Word tokens: type letter and length bucket |
| `page` `order` | Keys and XML names: lowercase, followed by zero or more word tokens |
| `GET` `POST` … | Method, uppercased |
| `HC1` | Header count bucket: fields (duplicates included) divided by 16, rounded up |
| `MIME application_json` | Media type from `Content-Type`, one lowercase value |
| `HOST example_com_8080` | Host, one lowercase value |
| `HEADERS` | Selected headers follow |
| `BODY JSON` / `XML` / `FORM` / `MULTIPART` / `OTHER` | Body follows, and its kind |
| `TRUE` `FALSE` `NULL` | JSON literals |
| `OE` `LE` | End of a JSON object or list |
| `EO` `EL` | An empty JSON object or list |
| `AE` | End of an XML element's attributes |
| `NA` | An XML element with no attributes |
| `TE` | End of an XML element |
| `EE` | End of an XML element with no text or children |
| `PART HS3` | A multipart part, with its header size bucket |
| `CLOK` `CLBAD` | `Content-Length` matched the body received, or not |
| `ERR` | The body failed to parse; nothing more is emitted for it |

The order is: method, path, query, `HC`, `MIME`, `HOST`,
`HEADERS`, `BODY`, `CLOK`/`CLBAD`.

### Word tokens

Every value is split on whitespace, and each piece becomes a word token:
its type and its length in bytes divided by 16, rounded up (1-16 bytes is
1, 17-32 is 2, …). A value with no pieces (empty, or only whitespace) is
`B0`.

- `A`: only ASCII letters and digits.
- `P`: printable ASCII, with punctuation.
- `B`: anything else (control characters, non-ASCII).

Path segments, query and form values are percent-decoded first (and `+` is
a space in queries and forms); invalid escapes are kept as they are. JSON
escapes and XML entities are decoded too.

### Keys

Keys and names are lowercased, and every run of characters outside
`[a-z0-9_]` becomes a single `_` (`content-type` → `content_type`,
`vnd.api+json` → `vnd_api_json`, `tags[]` → `tags_`). An empty key is `_`,
and each key is cut at 64 characters. This is not reversible, and keeps
every key regex-safe. The MIME type and host are normalised the same way.


### Parts

- **Path**: one word token per segment, between the method and the first
  key or `HC`; `/` alone is one empty segment, `B0`. An absolute
  URL target is traced by its path, and `*` is one segment.
- **Query**: the first lowercase word after the method begins it. Pairs
  are split on `&`, keys lowercased, and pairs sorted by key and then by
  their value's word tokens. A key without `=` has the value `B0`.
- **Headers**: after `HEADERS`, the fields `authorization`,
  `proxy_authorization`, `cookie`, `content_type`, `origin`,
  `access_control_request_method` and `access_control_request_headers`,
  each as its key and the word tokens of its value, sorted the same way.
  `cookie` has no value tokens: only whether there are cookies matters.
  Duplicates are all listed.
- **Body**, after `BODY` and its kind, chosen from the media type:
  - `JSON` (`application/json`, `*+json`): a walk of the document in
    order. Each key is emitted before its value, strings and numbers as
    their word tokens, and `true`, `false` and `null` as `TRUE`, `FALSE` and
    `NULL`. There are no start markers: the end of each object or array is
    `OE` or `LE`, and an empty object or array is `EO` or `EL` instead.
    Keys are in document order, not sorted. For example `{"a":{"b":[]}}`
    is `a b EL OE OE`.
  - `XML` (`application/xml`, `text/xml`, `*+xml`): a walk of the document
    in order, in the same style as JSON. Each element is emitted as its
    name, then its attributes (sorted, as for the query, each name followed
    by its value's word tokens) and `AE`, or just `NA` if it has none, then
    its text as word tokens and its children in document order, then `TE`; an element with no text or
    children (whitespace does not count) ends with `EE` instead. Namespace
    prefixes are part of the name (`soap:Body` → `soap_body`). Comments,
    processing instructions and declarations are skipped; CDATA is text.
    For example `<p lang="en">Hi <b>there</b></p>` is
    `p lang A1 AE A1 b NA A1 TE TE`.
  - `FORM` (`application/x-www-form-urlencoded`): as the query.
  - `MULTIPART` (`multipart/*`): each part as `PART`, `HS` and its header
    block's size bucket, and its field name from `Content-Disposition` if
    it has one. Part contents are skipped.
  - `OTHER`: anything else; only the kind is traced.
- `ERR` ends a body that does not parse (including a multipart body with
  no boundary, or that never ends), after whatever was traced before the
  error.
- `CLOK` / `CLBAD` appear only with a `Content-Length` header, once the body
  was read to its end or the client stopped sending it.

`MIME` is left out without a `Content-Type`, `HOST` without a Host,
`HEADERS` when none of the selected headers is present, and `BODY` when no
body bytes were read: a body the proxy never read, such as a request the
rules rejected, is not traced.

### Examples

`GET /blog/2026/10/my-post.html`:

```
GET A1 A1 A1 P1 HC1 HOST example_com
```

`GET /search?q=hello&page=2`:

```
GET A1 page A1 q A1 HC1 HOST example_com
```

A CORS preflight:

```
OPTIONS A1 A1 HC1 HOST example_com HEADERS access_control_request_headers P1 P1 access_control_request_method A1 origin P2
```

A JSON body:

```
PUT A1 A1 A1 HC1 MIME application_json HOST example_com HEADERS content_type P1 BODY JSON order id P3 items sku A1 qty A1 OE sku A1 qty A1 note B0 OE LE total P1 OE tags A1 A1 LE meta EO OE CLOK
```

An XML body:

```
POST A1 A1 HC1 MIME application_xml HOST example_com HEADERS content_type P1 BODY XML feed lang A1 AE title NA A1 TE entry id A1 AE title NA A1 TE body NA A1 P1 TE TE entry id A1 AE EE TE CLOK
```

A multipart upload:

```
POST A1 HC1 MIME multipart_form_data HOST example_com HEADERS content_type P2 P3 BODY MULTIPART PART HS3 title PART HS6 photo PART HS3 tags_ CLOK
```
