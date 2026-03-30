//go:build linux

package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	eUtils "github.com/apernet/hysteria/extras/v2/utils"
)

const firewallBackendEnv = "HYSTERIA_FIREWALL_BACKEND"

type osCommandRunner struct{}

func (osCommandRunner) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

func (osCommandRunner) Run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, string(out))
	}
	return nil
}

type closerFuncs struct {
	mu   sync.Mutex
	fns  []func()
	once sync.Once
}

func (c *closerFuncs) add(fn func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fns = append(c.fns, fn)
}

func (c *closerFuncs) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		for i := len(c.fns) - 1; i >= 0; i-- {
			c.fns[i]()
		}
		c.fns = nil
	})
	return nil
}

func SetupUDPPortRedirect(listenAddr *net.UDPAddr, ports eUtils.PortUnion) (*closerFuncs, error) {
	cleanup, err := setupUDPPortRedirectWithRunner(osCommandRunner{}, listenAddr, ports)
	if err != nil {
		return nil, err
	}
	return cleanup, nil
}

func setupUDPPortRedirectWithRunner(r commandRunner, listenAddr *net.UDPAddr, ports eUtils.PortUnion) (*closerFuncs, error) {
	redirects := redirectPortUnion(ports)
	if len(redirects) == 0 {
		return nil, nil
	}
	switch strings.ToLower(os.Getenv(firewallBackendEnv)) {
	case "nftables", "nft":
		return setupNFTablesRedirect(r, listenAddr, ports, redirects)
	case "iptables", "ipt":
		return setupIPTablesRedirect(r, listenAddr, ports, redirects)
	default:
		// Auto-detect: prefer nftables, fall back to iptables.
		if _, err := r.LookPath("nft"); err == nil {
			return setupNFTablesRedirect(r, listenAddr, ports, redirects)
		}
		return setupIPTablesRedirect(r, listenAddr, ports, redirects)
	}
}

func setupNFTablesRedirect(r commandRunner, listenAddr *net.UDPAddr, ports, redirects eUtils.PortUnion) (*closerFuncs, error) {
	families := nftFamiliesForAddr(listenAddr)
	cleanup := &closerFuncs{}
	nft := func(args ...string) error {
		return r.Run("nft", args...)
	}
	for _, family := range families {
		hash := shortHash("nft|" + family + "|" + hashInput(listenAddr, ports))
		tableName := "hysteria_" + hash
		if err := nft("add", "table", family, tableName); err != nil {
			_ = cleanup.Close()
			return nil, err
		}
		cleanup.add(func() { _ = nft("delete", "table", family, tableName) })
		for _, chainArgs := range [][]string{
			{"add", "chain", family, tableName, "prerouting", "{", "type", "nat", "hook", "prerouting", "priority", "dstnat;", "policy", "accept;", "}"},
			{"add", "chain", family, tableName, "output", "{", "type", "nat", "hook", "output", "priority", "dstnat;", "policy", "accept;", "}"},
		} {
			if err := nft(chainArgs...); err != nil {
				_ = cleanup.Close()
				return nil, err
			}
		}
		for _, chain := range []string{"prerouting", "output"} {
			for _, portRange := range redirects {
				args := []string{"add", "rule", family, tableName, chain}
				if match := nftDestinationMatch(family, listenAddr); match != nil {
					args = append(args, match...)
				}
				args = append(args, "udp", "dport", nftPortExpr(portRange), "redirect", "to", fmt.Sprintf(":%d", ports[0].Start))
				if err := nft(args...); err != nil {
					_ = cleanup.Close()
					return nil, err
				}
			}
		}
	}
	return cleanup, nil
}

func setupIPTablesRedirect(r commandRunner, listenAddr *net.UDPAddr, ports, redirects eUtils.PortUnion) (*closerFuncs, error) {
	bins, err := iptablesBinariesForAddr(r, listenAddr)
	if err != nil {
		return nil, err
	}
	cleanup := &closerFuncs{}
	for _, bin := range bins {
		ipt := func(args ...string) error {
			return r.Run(bin, append([]string{"-w"}, args...)...)
		}
		hash := shortHash(bin + "|" + hashInput(listenAddr, ports))
		chainName := "HYSTERIA-PR-" + hash
		if err := ipt("-t", "nat", "-N", chainName); err != nil {
			_ = cleanup.Close()
			return nil, err
		}
		cleanup.add(func() {
			_ = ipt("-t", "nat", "-F", chainName)
			_ = ipt("-t", "nat", "-X", chainName)
		})
		if err := ipt("-t", "nat", "-A", chainName, "-p", "udp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", ports[0].Start)); err != nil {
			_ = cleanup.Close()
			return nil, err
		}
		for _, baseChain := range []string{"PREROUTING", "OUTPUT"} {
			for _, portRange := range redirects {
				args := []string{"-t", "nat", "-A", baseChain}
				if match := iptablesDestinationMatch(listenAddr); match != nil {
					args = append(args, match...)
				}
				args = append(args, "-p", "udp", "--dport", iptablesPortExpr(portRange), "-j", chainName)
				if err := ipt(args...); err != nil {
					_ = cleanup.Close()
					return nil, err
				}
				deleteArgs := append([]string{"-t", "nat", "-D", baseChain}, args[4:]...)
				cleanup.add(func() { _ = ipt(deleteArgs...) })
			}
		}
	}
	return cleanup, nil
}

func nftFamiliesForAddr(addr *net.UDPAddr) []string {
	if addr.IP == nil || addr.IP.IsUnspecified() {
		return []string{"ip", "ip6"}
	}
	if addr.IP.To4() != nil {
		return []string{"ip"}
	}
	return []string{"ip6"}
}

func nftDestinationMatch(family string, addr *net.UDPAddr) []string {
	if addr.IP == nil || addr.IP.IsUnspecified() {
		return nil
	}
	if family == "ip6" {
		return []string{"ip6", "daddr", addr.IP.String()}
	}
	return []string{"ip", "daddr", addr.IP.String()}
}

func nftPortExpr(portRange eUtils.PortRange) string {
	if portRange.Start == portRange.End {
		return fmt.Sprintf("%d", portRange.Start)
	}
	return fmt.Sprintf("%d-%d", portRange.Start, portRange.End)
}

func iptablesBinariesForAddr(r commandRunner, addr *net.UDPAddr) ([]string, error) {
	if addr.IP == nil || addr.IP.IsUnspecified() {
		if _, err := r.LookPath("iptables"); err != nil {
			return nil, err
		}
		if _, err := r.LookPath("ip6tables"); err != nil {
			return nil, err
		}
		return []string{"iptables", "ip6tables"}, nil
	}
	if addr.IP.To4() != nil {
		if _, err := r.LookPath("iptables"); err != nil {
			return nil, err
		}
		return []string{"iptables"}, nil
	}
	if _, err := r.LookPath("ip6tables"); err != nil {
		return nil, err
	}
	return []string{"ip6tables"}, nil
}

func iptablesDestinationMatch(addr *net.UDPAddr) []string {
	if addr.IP == nil || addr.IP.IsUnspecified() {
		return nil
	}
	return []string{"-d", addr.IP.String()}
}

func iptablesPortExpr(portRange eUtils.PortRange) string {
	if portRange.Start == portRange.End {
		return fmt.Sprintf("%d", portRange.Start)
	}
	return fmt.Sprintf("%d:%d", portRange.Start, portRange.End)
}

func shortHash(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])[:8]
}
