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
