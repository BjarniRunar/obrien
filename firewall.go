package main

import (
	"bytes"
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

// nftTable holds every rule police installs, so removal is a single table
// delete that cannot touch anyone else's rules.
const nftTable = "inet police"

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

type FirewallOnArgs struct {
	Local bool `default:"false"`
}

func (p *Police) ApiFirewallOn(ri *kettlingar.RequestInfo, args FirewallOnArgs) *FirewallResponse {
	var incoming, local, notes []string
	for _, r := range []struct {
		from     int
		ln       net.Listener
		upstream *url.URL
	}{{80, p.httpLn, p.upstream}, {443, p.httpsLn, p.upstreamHttps}} {
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
		// Only connections addressed to this host are redirected. Without
		// the fib match, prerouting would also catch traffic routed through
		// the host, such as containers or VMs connecting out to port 443.
		rule := fmt.Sprintf("fib daddr type local tcp dport %d counter redirect to :%d", r.from, port)
		if !ip.IsLoopback() {
			incoming = append(incoming, rule)
		} else if !args.Local {
			return firewallFailed(ri, "", fmt.Errorf("listener %s is loopback-only and cannot receive redirected traffic; use --local true to redirect only local traffic", r.ln.Addr()))
		}
		if args.Local {
			if !ip.IsLoopback() && !ip.IsUnspecified() {
				return firewallFailed(ri, "", fmt.Errorf("listener %s is not reachable on loopback, where local traffic is redirected", r.ln.Addr()))
			}
			match := ""
			// An upstream on this port may be on this host, and police's
			// connections to it would be redirected back into police. They
			// can only be told apart by uid, which also exempts any client
			// running as the daemon's user.
			if upstreamPort(r.upstream) == r.from {
				match = fmt.Sprintf("meta skuid != %d ", os.Getuid()) + match
				notes = append(notes, fmt.Sprintf(
					"local connections to port %d from uid %d (police's user) are not redirected, so police can reach its upstream %s\n",
					r.from, os.Getuid(), r.upstream))
			}
			local = append(local, match+rule)
		}
	}
	if len(incoming) == 0 && len(local) == 0 {
		return firewallFailed(ri, "", fmt.Errorf("no listener needs redirecting"))
	}
	script := deleteTableScript() + "table " + nftTable + " {\n" +
		natChain("prerouting", "prerouting priority dstnat", incoming) +
		natChain("output", "output priority -100", local) + "}\n"
	if out, err := runNft(script); err != nil {
		return firewallFailed(ri, out, err)
	}
	p.ks.Logger.Info(serviceName+": firewall redirect installed", "incoming", len(incoming), "local", len(local))
	status := p.ApiFirewallStatus(ri)
	status.Output = strings.Join(notes, "") + status.Output
	return status
}

// upstreamPort returns the TCP port police connects to for its upstream.
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

func (p *Police) ApiFirewallOff(ri *kettlingar.RequestInfo) *FirewallResponse {
	if out, err := runNft(deleteTableScript()); err != nil {
		return firewallFailed(ri, out, err)
	}
	p.ks.Logger.Info(serviceName + ": firewall redirect removed")
	return &FirewallResponse{Output: "removed table " + nftTable + "\n"}
}

func (p *Police) ApiFirewallStatus(ri *kettlingar.RequestInfo) *FirewallResponse {
	out, err := sudoNft(nil, "list", "table", nftTable)
	if err != nil {
		return firewallFailed(ri, out, err)
	}
	return &FirewallResponse{Output: out}
}

func firewallFailed(ri *kettlingar.RequestInfo, out string, err error) *FirewallResponse {
	ri.HttpCode = http.StatusInternalServerError
	return &FirewallResponse{Output: out, Error: err.Error()}
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

// deleteTableScript removes the police table whether or not it exists:
// declaring an empty table first makes the delete always succeed, and older
// nft releases lack "destroy table".
func deleteTableScript() string {
	return fmt.Sprintf("table %s\ndelete table %s\n", nftTable, nftTable)
}

// runNft applies the script as one nft transaction, so a failure leaves the
// previous ruleset in place.
func runNft(script string) (string, error) {
	return sudoNft(strings.NewReader(script), "-f", "-")
}

// sudoNft uses "sudo -n" because the daemon has no terminal: a password
// prompt would hang the RPC call instead of failing it.
func sudoNft(stdin *strings.Reader, args ...string) (string, error) {
	cmd := exec.Command("sudo", append([]string{"-n", "nft"}, args...)...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}
