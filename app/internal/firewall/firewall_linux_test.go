//go:build linux

package firewall

import (
	"errors"
	"net"
	"testing"

	eUtils "github.com/apernet/hysteria/extras/v2/utils"
	"github.com/stretchr/testify/require"
)

type fakeRunner struct {
	paths map[string]bool
	cmds  [][]string
	fail  int
}

func (r *fakeRunner) LookPath(file string) (string, error) {
	if r.paths[file] {
		return "/usr/sbin/" + file, nil
	}
	return "", errors.New("not found")
}

func (r *fakeRunner) Run(name string, args ...string) error {
	r.cmds = append(r.cmds, append([]string{name}, args...))
	if r.fail > 0 && len(r.cmds) == r.fail {
		return errors.New("boom")
	}
	return nil
}

func TestSetupUDPPortRedirectWithRunnerNFTables(t *testing.T) {
	runner := &fakeRunner{paths: map[string]bool{"nft": true}}
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 20000}
	ports := eUtils.PortUnion{{20000, 20002}}

	cleanup, err := setupUDPPortRedirectWithRunner(runner, addr, ports)
	require.NoError(t, err)
	require.NotNil(t, cleanup)
	require.Contains(t, runner.cmds[0], "add")
	require.Contains(t, runner.cmds[0], "table")
	require.Contains(t, runner.cmds[3], "udp")
	require.Contains(t, runner.cmds[3], "dport")
	require.Contains(t, runner.cmds[3], "20001-20002")
	require.Contains(t, runner.cmds[3], ":20000")

	require.NoError(t, cleanup.Close())
	require.Contains(t, runner.cmds[len(runner.cmds)-1], "delete")
}

func TestSetupUDPPortRedirectWithRunnerIPTablesFallback(t *testing.T) {
	runner := &fakeRunner{paths: map[string]bool{"iptables": true}}
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 20000}
	ports := eUtils.PortUnion{{20000, 20000}, {20002, 20003}}

	cleanup, err := setupUDPPortRedirectWithRunner(runner, addr, ports)
	require.NoError(t, err)
	require.NotNil(t, cleanup)
	require.Equal(t, "iptables", runner.cmds[0][0])
	require.Contains(t, runner.cmds[0], "-N")
	require.Contains(t, runner.cmds[1], "REDIRECT")
	require.Contains(t, runner.cmds[2], "PREROUTING")
	require.Contains(t, runner.cmds[2], "20002:20003")

	require.NoError(t, cleanup.Close())
	foundDelete := false
	for _, cmd := range runner.cmds {
		for _, arg := range cmd {
			if arg == "-D" {
				foundDelete = true
				break
			}
		}
	}
	require.True(t, foundDelete)
}

func TestSetupUDPPortRedirectWithRunnerNFTablesIPv6Specific(t *testing.T) {
	runner := &fakeRunner{paths: map[string]bool{"nft": true}}
	addr := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 20000}
	ports := eUtils.PortUnion{{20000, 20002}}

	cleanup, err := setupUDPPortRedirectWithRunner(runner, addr, ports)
	require.NoError(t, err)
	require.NotNil(t, cleanup)

	for _, cmd := range runner.cmds {
		hasUDP := false
		for _, arg := range cmd {
			if arg == "udp" {
				hasUDP = true
				break
			}
		}
		if !hasUDP {
			continue
		}
		hasDnat := false
		hasRedirect := false
		for _, arg := range cmd {
			if arg == "dnat" {
				hasDnat = true
			}
			if arg == "redirect" {
				hasRedirect = true
			}
		}
		require.True(t, hasDnat, "IPv6 specific address rule should use dnat: %v", cmd)
		require.False(t, hasRedirect, "IPv6 specific address rule must not use redirect: %v", cmd)
		require.Contains(t, cmd, "[2001:db8::1]:20000")
	}

	require.NoError(t, cleanup.Close())
}

func TestSetupUDPPortRedirectWithRunnerNFTablesIPv6Unspecified(t *testing.T) {
	runner := &fakeRunner{paths: map[string]bool{"nft": true}}
	addr := &net.UDPAddr{IP: net.IPv6unspecified, Port: 20000}
	ports := eUtils.PortUnion{{20000, 20002}}

	cleanup, err := setupUDPPortRedirectWithRunner(runner, addr, ports)
	require.NoError(t, err)
	require.NotNil(t, cleanup)

	for _, cmd := range runner.cmds {
		hasDnat := false
		for _, arg := range cmd {
			if arg == "dnat" {
				hasDnat = true
				break
			}
		}
		require.False(t, hasDnat, "IPv6 unspecified address rule must not use dnat: %v", cmd)
	}

	require.NoError(t, cleanup.Close())
}

func TestSetupUDPPortRedirectWithRunnerIPTablesIPv6Specific(t *testing.T) {
	runner := &fakeRunner{paths: map[string]bool{"ip6tables": true}}
	addr := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 20000}
	ports := eUtils.PortUnion{{20000, 20002}}

	cleanup, err := setupUDPPortRedirectWithRunner(runner, addr, ports)
	require.NoError(t, err)
	require.NotNil(t, cleanup)

	foundTarget := false
	for _, cmd := range runner.cmds {
		hasDNAT := false
		hasREDIRECT := false
		for _, arg := range cmd {
			if arg == "DNAT" {
				hasDNAT = true
			}
			if arg == "REDIRECT" {
				hasREDIRECT = true
			}
		}
		require.False(t, hasREDIRECT, "IPv6 specific address rule must not use REDIRECT: %v", cmd)
		if hasDNAT {
			foundTarget = true
			require.Contains(t, cmd, "[2001:db8::1]:20000")
		}
	}
	require.True(t, foundTarget, "expected a DNAT rule for specific IPv6 bind")

	require.NoError(t, cleanup.Close())
}

func TestSetupUDPPortRedirectWithRunnerIPTablesIPv6Unspecified(t *testing.T) {
	runner := &fakeRunner{paths: map[string]bool{"iptables": true, "ip6tables": true}}
	addr := &net.UDPAddr{IP: net.IPv6unspecified, Port: 20000}
	ports := eUtils.PortUnion{{20000, 20002}}

	cleanup, err := setupUDPPortRedirectWithRunner(runner, addr, ports)
	require.NoError(t, err)
	require.NotNil(t, cleanup)

	for _, cmd := range runner.cmds {
		for _, arg := range cmd {
			require.NotEqual(t, "DNAT", arg, "unspecified address rule must not use DNAT: %v", cmd)
		}
	}

	require.NoError(t, cleanup.Close())
}

func TestSetupUDPPortRedirectWithRunnerIPTablesIPv4Specific(t *testing.T) {
	runner := &fakeRunner{paths: map[string]bool{"iptables": true}}
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 20000}
	ports := eUtils.PortUnion{{20000, 20002}}

	cleanup, err := setupUDPPortRedirectWithRunner(runner, addr, ports)
	require.NoError(t, err)
	require.NotNil(t, cleanup)

	foundRedirect := false
	for _, cmd := range runner.cmds {
		for _, arg := range cmd {
			require.NotEqual(t, "DNAT", arg, "IPv4 rule must keep REDIRECT, not DNAT: %v", cmd)
			if arg == "REDIRECT" {
				foundRedirect = true
			}
		}
	}
	require.True(t, foundRedirect, "expected REDIRECT rule for IPv4 bind")

	require.NoError(t, cleanup.Close())
}

func TestSetupUDPPortRedirectWithRunnerRollback(t *testing.T) {
	runner := &fakeRunner{
		paths: map[string]bool{"iptables": true},
		fail:  3,
	}
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 20000}
	ports := eUtils.PortUnion{{20000, 20001}}

	_, err := setupUDPPortRedirectWithRunner(runner, addr, ports)
	require.Error(t, err)
	require.Contains(t, runner.cmds[len(runner.cmds)-1], "-X")
}
