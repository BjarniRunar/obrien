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
// output of rules-list -f json can be read back; Matches is ignored there.
type RulesResponse struct {
	Rules []RuleEntry `msgpack:"rules" json:"rules"`
	Error string      `msgpack:"error" json:"error,omitempty"`
}

// RuleEntry is a pattern and its rules_matched_total count. The metric is
// keyed by name, so the count survives replacing or re-adding a rule under
// the same name, and only resets when the daemon restarts.
type RuleEntry struct {
	Name    string `msgpack:"name" json:"name"`
	Regexp  string `msgpack:"regexp" json:"regexp"`
	Matches uint64 `msgpack:"matches" json:"matches"`
}

func (r *RulesResponse) String() string {
	if r.Error != "" {
		return "error: " + r.Error
	}
	if len(r.Rules) == 0 {
		return "(no rules)"
	}
	width, mwidth := len("NAME"), len("MATCHES")
	for _, p := range r.Rules {
		width = max(width, len(p.Name))
		mwidth = max(mwidth, len(fmt.Sprint(p.Matches)))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-*s  %*s  %s\n", width, "NAME", mwidth, "MATCHES", "REGEXP")
	for _, p := range r.Rules {
		fmt.Fprintf(&b, "%-*s  %*d  %s\n", width, p.Name, mwidth, p.Matches, p.Regexp)
	}
	return b.String()
}

func (p *Police) rulesResult(ri *kettlingar.RequestInfo, err error) *RulesResponse {
	if err != nil {
		ri.HttpCode = http.StatusBadRequest
		return &RulesResponse{Error: err.Error()}
	}
	var entries []RuleEntry
	for _, pat := range p.patterns.List() {
		entries = append(entries, RuleEntry{
			Name:    pat.Name,
			Regexp:  pat.Regexp,
			Matches: p.ks.MetricsCountValue("rules_matched_total", kettlingar.PublicMetric, kettlingar.MetricLabels{"rule": pat.Name}),
		})
	}
	return &RulesResponse{Rules: entries}
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
	add := make([]rules.Pattern, len(f.Rules))
	for i, e := range f.Rules {
		add[i] = rules.Pattern{Name: e.Name, Regexp: e.Regexp}
	}
	return add, nil
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
