package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/mailpile/kettlingar-go/kettlingar"

	"police/rules"
)

// RulesResponse is also the file format of rules-add --file, so that the
// output of rules-list -f json can be read back.
type RulesResponse struct {
	Rules []rules.Pattern `msgpack:"rules" json:"rules"`
	Error string          `msgpack:"error" json:"error,omitempty"`
}

func (r *RulesResponse) String() string {
	if r.Error != "" {
		return "error: " + r.Error
	}
	if len(r.Rules) == 0 {
		return "(no rules)"
	}
	width := len("NAME")
	for _, p := range r.Rules {
		width = max(width, len(p.Name))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-*s  %s\n", width, "NAME", "REGEXP")
	for _, p := range r.Rules {
		fmt.Fprintf(&b, "%-*s  %s\n", width, p.Name, p.Regexp)
	}
	return b.String()
}

func (p *Police) rulesResult(ri *kettlingar.RequestInfo, err error) *RulesResponse {
	if err != nil {
		ri.HttpCode = http.StatusBadRequest
		return &RulesResponse{Error: err.Error()}
	}
	return &RulesResponse{Rules: p.patterns.List()}
}

func (p *Police) ApiRulesList(ri *kettlingar.RequestInfo) *RulesResponse {
	return p.rulesResult(ri, nil)
}

type RulesAddArgs struct {
	Args    []string
	Replace string
	File    string
}

func (p *Police) ApiRulesAdd(ri *kettlingar.RequestInfo, args RulesAddArgs) *RulesResponse {
	var add []rules.Pattern
	switch {
	case args.File != "" && len(args.Args) > 0:
		return p.rulesResult(ri, errors.New("give either NAME REGEXP or --file, not both"))
	case args.File != "":
		var err error
		if add, err = readRulesFile(args.File); err != nil {
			return p.rulesResult(ri, err)
		}
	case len(args.Args) == 2:
		add = []rules.Pattern{{Name: args.Args[0], Regexp: args.Args[1]}}
	default:
		return p.rulesResult(ri, errors.New("usage: rules-add [--replace OLD] NAME REGEXP, or rules-add --file PATH"))
	}
	err := p.patterns.Add(add, args.Replace)
	if err == nil {
		p.ks.Logger.Info(serviceName+": rules added", "count", len(add), "replaced", args.Replace)
	}
	return p.rulesResult(ri, err)
}

// readRulesFile runs in the daemon, whose working directory is not the
// caller's, so relative paths are refused rather than misresolved.
func readRulesFile(path string) ([]rules.Pattern, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("--file %q must be an absolute path", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f RulesResponse
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return f.Rules, nil
}

type RulesRmArgs struct {
	Args []string
}

func (p *Police) ApiRulesRm(ri *kettlingar.RequestInfo, args RulesRmArgs) *RulesResponse {
	err := p.patterns.Remove(args.Args)
	if err == nil {
		p.ks.Logger.Info(serviceName+": rules removed", "names", strings.Join(args.Args, " "))
	}
	return p.rulesResult(ri, err)
}
