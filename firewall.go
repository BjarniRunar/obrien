// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/mailpile/kettlingar-go/kettlingar"
)

// nftTable holds every rule obrien installs, so removal is a single table
// delete that cannot touch anyone else's rules.
const nftTable = "inet obrien"

type FirewallResponse struct {
	Output string `msgpack:"output" json:"output"`
	Error  string `msgpack:"error" json:"error,omitempty"`
}

func (r *FirewallResponse) String() string {
	if r.Error != "" {
		return r.Output + "error: " + r.Error
	}
	return r.Output
}

type FirewallArgs struct {
	Mode string `default:"auto" help:"Firewalling tool: nft, iptables or auto"`
}

type FirewallOnArgs struct {
	Local bool   `default:"false"`
	Mode  string `default:"auto" help:"Firewalling tool: nft, iptables or auto"`
}

// redirect sends TCP traffic for this host's port From to obrien's port To.
// ExemptUid is the uid whose local connections are not redirected, or -1.
type redirect struct {
	From, To  int
	Local     bool
	ExemptUid int
}

func (p *Obrien) ApiFirewallOn(ri *kettlingar.RequestInfo, args FirewallOnArgs) *FirewallResponse {
	fw, err := findFirewall(args.Mode)
	if err != nil {
		return firewallFailed(ri, "", err)
	}
	var rules []redirect
	var notes []string
	for _, r := range []struct {
		from int
		ln   net.Listener
	}{{80, p.httpLn}, {443, p.httpsLn}} {
		if r.ln == nil {
			continue
		}
		ip, port, err := listenerAddr(r.ln.Addr())
		if err != nil {
			return firewallFailed(ri, "", err)
		}
		if port == r.from {
			continue
		}
		if !ip.IsLoopback() {
			rules = append(rules, redirect{From: r.from, To: port, ExemptUid: -1})
		} else if !args.Local {
			return firewallFailed(ri, "", fmt.Errorf("listener %s is loopback-only and cannot receive redirected traffic; use --local true to redirect only local traffic", r.ln.Addr()))
		}
		if args.Local {
			if !ip.IsLoopback() && !ip.IsUnspecified() {
				return firewallFailed(ri, "", fmt.Errorf("listener %s is not reachable on loopback, where local traffic is redirected", r.ln.Addr()))
			}
			rule := redirect{From: r.from, To: port, Local: true, ExemptUid: -1}
			// Either listener's upstream on this port may be on this host,
			// and obrien's connections to it would be redirected back into
			// obrien. They can only be told apart by uid, which also exempts
			// any client running as the daemon's user.
			if upstreamPort(p.upstream) == r.from || upstreamPort(p.upstreamHttps) == r.from {
				rule.ExemptUid = os.Getuid()
				notes = append(notes, fmt.Sprintf(
					"# local connections to port %d from uid %d (obrien's user) are not redirected, so obrien can reach its upstream\n",
					r.from, os.Getuid()))
			}
			rules = append(rules, rule)
		}
	}
	if len(rules) == 0 {
		return firewallFailed(ri, "", fmt.Errorf("no listener needs redirecting"))
	}
	return &FirewallResponse{Output: fw.script(strings.Join(notes, "") + fw.on(rules))}
}

func (p *Obrien) ApiFirewallOff(ri *kettlingar.RequestInfo, args FirewallArgs) *FirewallResponse {
	fw, err := findFirewall(args.Mode)
	if err != nil {
		return firewallFailed(ri, "", err)
	}
	return &FirewallResponse{Output: fw.script(fw.off())}
}

func (p *Obrien) ApiFirewallStatus(ri *kettlingar.RequestInfo, args FirewallArgs) *FirewallResponse {
	fw, err := findFirewall(args.Mode)
	if err != nil {
		return firewallFailed(ri, "", err)
	}
	return &FirewallResponse{Output: fw.script(fw.status())}
}

func firewallFailed(ri *kettlingar.RequestInfo, out string, err error) *FirewallResponse {
	ri.HttpCode = http.StatusInternalServerError
	return &FirewallResponse{Output: out, Error: err.Error()}
}

// firewall renders shell scripts for one of the host's firewalling tools.
// Tool paths are absolute, as root's PATH may differ from the daemon's.
type firewall struct {
	nft, iptables, ip6tables string
}

// findFirewall in auto mode prefers nft in /usr/sbin, then iptables (with
// ip6tables if present), looked up in the sbin directories and the daemon's
// PATH. A named mode never fails: a tool not found here is used by bare name,
// so scripts can be made for other hosts.
func findFirewall(mode string) (*firewall, error) {
	switch mode {
	case "nft":
		return &firewall{nft: findToolOr("nft")}, nil
	case "iptables":
		return &firewall{iptables: findToolOr("iptables"), ip6tables: findToolOr("ip6tables")}, nil
	case "auto":
	default:
		return nil, fmt.Errorf("unknown mode %q: use nft, iptables or auto", mode)
	}
	if isExecutable("/usr/sbin/nft") {
		return &firewall{nft: "/usr/sbin/nft"}, nil
	}
	fw := &firewall{iptables: findTool("iptables"), ip6tables: findTool("ip6tables")}
	if fw.iptables == "" {
		return nil, fmt.Errorf("found neither /usr/sbin/nft nor iptables")
	}
	return fw, nil
}

func findTool(name string) string {
	for _, dir := range []string{"/usr/sbin", "/sbin"} {
		if path := dir + "/" + name; isExecutable(path) {
			return path
		}
	}
	path, _ := exec.LookPath(name)
	return path
}

func findToolOr(name string) string {
	if path := findTool(name); path != "" {
		return path
	}
	return name
}

func isExecutable(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0
}

func (fw *firewall) script(body string) string {
	s := "#!/bin/sh\n# pipe me to sudo or run as root\n"
	if fw.nft == "" && fw.ip6tables == "" {
		s += "# ip6tables not found: IPv6 is not covered\n"
	}
	return s + body
}

func (fw *firewall) on(rules []redirect) string {
	if fw.nft != "" {
		var incoming, local []string
		for _, r := range rules {
			// Only connections addressed to this host are redirected. Without
			// the fib match, prerouting would also catch traffic routed through
			// the host, such as containers or VMs connecting out to port 443.
			rule := fmt.Sprintf("fib daddr type local tcp dport %d counter redirect to :%d", r.From, r.To)
			if r.ExemptUid >= 0 {
				rule = fmt.Sprintf("meta skuid != %d ", r.ExemptUid) + rule
			}
			if r.Local {
				local = append(local, rule)
			} else {
				incoming = append(incoming, rule)
			}
		}
		return fw.nftScript(deleteTableScript() + "table " + nftTable + " {\n" +
			natChain("prerouting", "prerouting priority dstnat", incoming) +
			natChain("output", "output priority -100", local) + "}\n")
	}
	s := fw.off() + "set -e\n"
	for _, tool := range fw.iptablesTools() {
		for _, c := range iptablesChains {
			s += fmt.Sprintf("%s -t nat -N %s\n", tool, c.own)
		}
		for _, r := range rules {
			chain, match := iptablesChains[0].own, ""
			if r.Local {
				chain = iptablesChains[1].own
			}
			if r.ExemptUid >= 0 {
				match = fmt.Sprintf(" -m owner ! --uid-owner %d", r.ExemptUid)
			}
			s += fmt.Sprintf("%s -t nat -A %s -p tcp --dport %d -m addrtype --dst-type LOCAL%s -j REDIRECT --to-ports %d\n",
				tool, chain, r.From, match, r.To)
		}
		for _, c := range iptablesChains {
			s += fmt.Sprintf("%s -t nat -A %s -j %s\n", tool, c.builtin, c.own)
		}
	}
	return s
}

func (fw *firewall) off() string {
	if fw.nft != "" {
		return fw.nftScript(deleteTableScript())
	}
	s := ""
	for _, tool := range fw.iptablesTools() {
		for _, c := range iptablesChains {
			s += fmt.Sprintf("while %s -t nat -D %s -j %s 2>/dev/null; do :; done\n", tool, c.builtin, c.own)
			s += fmt.Sprintf("%s -t nat -F %s 2>/dev/null\n", tool, c.own)
			s += fmt.Sprintf("%s -t nat -X %s 2>/dev/null\n", tool, c.own)
		}
	}
	return s
}

func (fw *firewall) status() string {
	if fw.nft != "" {
		return fmt.Sprintf("%s list table %s\n", fw.nft, nftTable)
	}
	s := ""
	for _, tool := range fw.iptablesTools() {
		for _, c := range iptablesChains {
			s += fmt.Sprintf("%s -t nat -L %s -n -v\n", tool, c.own)
		}
	}
	return s
}

// nftScript runs the script as one nft transaction, so a failure leaves the
// previous ruleset in place. nft reads its arguments as a script.
func (fw *firewall) nftScript(script string) string {
	return fw.nft + " '\n" + script + "'\n"
}

func (fw *firewall) iptablesTools() []string {
	if fw.ip6tables == "" {
		return []string{fw.iptables}
	}
	return []string{fw.iptables, fw.ip6tables}
}

// iptablesChains are obrien's own nat chains, each reached by one jump from
// a built-in chain, so removal never touches anyone else's rules. Unlike
// nft, iptables changes are not atomic.
var iptablesChains = []struct{ builtin, own string }{
	{"PREROUTING", "OBRIEN-PRE"},
	{"OUTPUT", "OBRIEN-OUT"},
}

// upstreamPort returns the TCP port obrien connects to for its upstream.
func upstreamPort(u *url.URL) int {
	if port, err := strconv.Atoi(u.Port()); err == nil {
		return port
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}

// natChain renders a nat chain, or nothing when it has no rules.
func natChain(name, hook string, rules []string) string {
	if len(rules) == 0 {
		return ""
	}
	return fmt.Sprintf("\tchain %s {\n\t\ttype nat hook %s; policy accept;\n\t\t%s\n\t}\n",
		name, hook, strings.Join(rules, "\n\t\t"))
}

// listenerAddr splits a bound listener's address. "redirect" rewrites the
// destination to the receiving interface's own address for incoming traffic,
// and to loopback for local traffic, which decides which listeners each
// kind of redirect can reach.
func listenerAddr(addr net.Addr) (net.IP, int, error) {
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, 0, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("listener %s has no IP address", addr)
	}
	port, err := strconv.Atoi(portStr)
	return ip, port, err
}

// deleteTableScript removes the obrien table whether or not it exists:
// declaring an empty table first makes the delete always succeed, and older
// nft releases lack "destroy table".
func deleteTableScript() string {
	return fmt.Sprintf("table %s\ndelete table %s\n", nftTable, nftTable)
}
