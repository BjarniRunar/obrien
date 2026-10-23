// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net/http"
	"strings"

	"github.com/mailpile/kettlingar-go/kettlingar"
)

type RequestsArgs struct {
	Count int `default:"50"`
}

// RequestsResponse holds trace log lines, each ending in a newline.
type RequestsResponse struct {
	Requests []string `msgpack:"requests" json:"requests"`
	Error    string   `msgpack:"error" json:"error,omitempty"`
}

func (r *RequestsResponse) String() string {
	if r.Error != "" {
		return "error: " + r.Error
	}
	return strings.Join(r.Requests, "")
}

func (p *Obrien) ApiRequests(ri *kettlingar.RequestInfo, args RequestsArgs) *RequestsResponse {
	if p.log == nil {
		ri.HttpCode = http.StatusNotFound
		return &RequestsResponse{Error: "request log is disabled (--request-log 0)"}
	}
	return &RequestsResponse{Requests: p.log.Recent(args.Count)}
}
