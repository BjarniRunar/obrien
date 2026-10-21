package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mailpile/kettlingar-go/kettlingar"

	"obrien/monitor"
)

type RequestsArgs struct {
	Count int `default:"50"`
}

type RequestsResponse struct {
	Requests []monitor.Record `msgpack:"requests" json:"requests"`
	Error    string           `msgpack:"error" json:"error,omitempty"`
}

func (r *RequestsResponse) String() string {
	if r.Error != "" {
		return "error: " + r.Error
	}
	var b strings.Builder
	for _, rec := range r.Requests {
		fmt.Fprintf(&b, "%s %-5s %s %d %s %s%s %s %s\n",
			rec.Time.Format(time.RFC3339Nano), rec.Listener, rec.RemoteAddr, rec.Status,
			rec.Method, rec.Host, rec.URI, rec.Proto, rec.Duration.Round(time.Microsecond))
	}
	return b.String()
}

func (p *Obrien) ApiRequests(ri *kettlingar.RequestInfo, args RequestsArgs) *RequestsResponse {
	if p.log == nil {
		ri.HttpCode = http.StatusNotFound
		return &RequestsResponse{Error: "request log is disabled (--request-log 0)"}
	}
	return &RequestsResponse{Requests: p.log.Recent(args.Count)}
}
