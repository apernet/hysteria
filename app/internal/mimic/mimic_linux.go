package mimic

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

const (
	runtimeDir     = "/run/mimic"
	readyTimeout   = 10 * time.Second
	readyPollEvery = 100 * time.Millisecond
)

type Instance struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
	logger *zap.Logger

	mu      sync.Mutex
	stopped bool
	exited  chan struct{}
}

// Start launches Mimic for addrs and waits for it to attach. addrs holds every
// address the peer resolved to for RoleClient, and our listen address for
// RoleServer.
// onExit is called if Mimic stops on its own, which is fatal: the peer expects
// TCP-shaped packets, so the connection is already dead by then.
func Start(cfg Config, role Role, addrs []*net.UDPAddr, logger *zap.Logger, onExit func(error)) (*Instance, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if len(addrs) == 0 {
		return nil, errors.New("mimic needs at least one address to filter")
	}
	bin, err := resolveBinary(cfg.Path)
	if err != nil {
		return nil, err
	}
	iface, err := resolveInterface(cfg.Interface, role, addrs[0])
	if err != nil {
		return nil, err
	}
	filters := filtersFor(role, addrs)
	// Mimic attaches to the interface, so one instance serves every client on
	// this machine reaching the same server.
	// Reuse it only if its filters cover our address.
	if pid, ok := runningOn(iface); ok {
		covered, err := filtersCover(bin, iface, filters)
		if err != nil {
			return nil, fmt.Errorf("mimic is already running on %s (pid %d) "+
				"and its filters could not be read: %w", iface, pid, err)
		}
		if !covered {
			return nil, fmt.Errorf("mimic is already running on %s (pid %d) but does "+
				"not cover the required filter set (%s); stop it, or update its filters",
				iface, pid, strings.Join(filterAddrs(filters), ", "))
		}
		logger.Info("using the mimic already running on this interface",
			zap.String("interface", iface), zap.Int("pid", pid))
		return nil, nil
	}

	args := runArgs(iface, filters, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, args...)
	// Mimic must outlive its own SIGINT handling on shutdown, so stop it with
	// SIGTERM and give it a moment to detach its BPF programs cleanly.
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 5 * time.Second
	// Ask the kernel to kill Mimic if we die without getting to stop it. A
	// surviving instance would keep rewriting packets for a Hysteria that is no
	// longer there, and would block the next start.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to start mimic: %w", err)
	}

	i := &Instance{cmd: cmd, cancel: cancel, logger: logger, exited: make(chan struct{})}
	go i.pipeLogs(stderr)
	go i.wait(onExit)

	if err := waitReady(iface, cmd.Process.Pid, i.exited); err != nil {
		_ = i.Close()
		return nil, err
	}
	logger.Info("mimic started",
		zap.String("interface", iface),
		zap.Strings("filters", filters))
	return i, nil
}

func runArgs(iface string, filters []string, cfg Config) []string {
	args := []string{"run", iface}
	for _, filter := range filters {
		args = append(args, "-f", filter)
	}
	if cfg.XDPMode != "" {
		args = append(args, "--xdp-mode", cfg.XDPMode)
	}
	return append(args, cfg.ExtraArgs...)
}

// Close stops Mimic and waits for it to detach.
func (i *Instance) Close() error {
	if i == nil {
		return nil
	}
	i.mu.Lock()
	i.stopped = true
	i.mu.Unlock()
	i.cancel()
	<-i.exited
	return nil
}

func (i *Instance) wait(onExit func(error)) {
	err := i.cmd.Wait()
	close(i.exited)
	i.mu.Lock()
	expected := i.stopped
	i.mu.Unlock()
	if !expected && onExit != nil {
		onExit(fmt.Errorf("mimic exited unexpectedly: %w", err))
	}
}

// pipeLogs forwards Mimic's output into our logger. Mimic writes its own level
// prefixes and colours; we keep the line as-is rather than trying to parse it.
func (i *Instance) pipeLogs(r io.Reader) {
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := strings.TrimSpace(stripANSI(s.Text()))
		if line != "" {
			i.logger.Info("mimic", zap.String("output", line))
		}
	}
}

// stripANSI removes the colour escapes Mimic writes.
func stripANSI(s string) string { return ansiRe.ReplaceAllString(s, "") }

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func resolveBinary(path string) (string, error) {
	if path != "" {
		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("mimic not found at %s: %w", path, err)
		}
		return path, nil
	}
	bin, err := exec.LookPath("mimic")
	if err != nil {
		return "", errors.New("mimic not found in PATH; install it from https://github.com/hack3ric/mimic")
	}
	return bin, nil
}

// runningOn reports whether a Mimic already owns the interface. Mimic only
// removes its lock file on a clean exit, so check the PID it records rather
// than treating a leftover file as a live instance.
func runningOn(iface string) (int, bool) {
	locks, err := lockFiles(iface)
	if err != nil {
		return 0, false
	}
	for _, lock := range locks {
		pid, err := lockPID(lock)
		if err != nil {
			// Unreadable: assume stale rather than block forever.
			continue
		}
		if processAlive(pid) {
			return pid, true
		}
	}
	return 0, false
}

// filtersCover reports whether the running Mimic already matches our address.
// "mimic show" prints one "Filter: origin=ip:port" line per whitelist entry.
func filtersCover(bin, iface string, filters []string) (bool, error) {
	out, err := exec.Command(bin, "show", iface).Output()
	if err != nil {
		return false, err
	}
	covered := make(map[string]bool)
	for _, line := range strings.Split(stripANSI(string(out)), "\n") {
		_, v, ok := strings.Cut(line, "Filter:")
		if ok {
			covered[filterAddr(strings.TrimSpace(v))] = true
		}
	}
	for _, want := range filterAddrs(filters) {
		if !covered[want] {
			return false, nil
		}
	}
	return true, nil
}

// filterAddr strips everything a filter line may carry beyond origin=ip:port:
// the settings after a comma, and the "(resolved from <host>)" note that
// "mimic show" appends when the filter came from a name rather than a literal.
func filterAddr(filter string) string {
	addr, _, _ := strings.Cut(filter, ",")
	addr, _, _ = strings.Cut(strings.TrimSpace(addr), " ")
	return addr
}

func filterAddrs(filters []string) []string {
	addrs := make([]string, len(filters))
	for i, filter := range filters {
		addrs[i] = filterAddr(filter)
	}
	return addrs
}

// lockPID reads the PID from a Mimic lock file, a flat key=value list.
func lockPID(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok && strings.TrimSpace(k) == "pid" {
			return strconv.Atoi(strings.TrimSpace(v))
		}
	}
	return 0, errors.New("no pid in lock file")
}

func processAlive(pid int) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

// lockFiles finds Mimic's lock files for iface. The name also encodes a network
// namespace ID, so match on the interface index only.
func lockFiles(iface string) ([]string, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	return filepath.Glob(fmt.Sprintf("%s/*_%d.lock", runtimeDir, ifi.Index))
}

// waitReady blocks until Mimic writes its lock file, signalling it has
// attached. Sending before that means packets Mimic isn't yet rewriting.
func waitReady(iface string, ourPID int, exited <-chan struct{}) error {
	deadline := time.Now().Add(readyTimeout)
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			return errors.New("mimic exited during startup; see log output above")
		default:
		}
		if locks, err := lockFiles(iface); err == nil {
			for _, lock := range locks {
				// Only our own child counts; a leftover file reads as ready.
				if pid, err := lockPID(lock); err == nil && pid == ourPID {
					return nil
				}
			}
		}
		time.Sleep(readyPollEvery)
	}
	return fmt.Errorf("mimic did not become ready within %s", readyTimeout)
}

// filtersFor builds Mimic's whitelist entries: the client matches on the peer,
// the server on itself. A server listener with no IP or an IPv6 wildcard
// accepts both address families, so Mimic needs one local filter for each. A
// client gets one filter per address the peer resolved to.
func filtersFor(role Role, addrs []*net.UDPAddr) []string {
	if role == RoleClient {
		filters := make([]string, 0, len(addrs))
		seen := make(map[string]bool, len(addrs))
		for _, addr := range addrs {
			f := fmt.Sprintf("remote=%s:%d", filterHost(addr.IP), addr.Port)
			if seen[f] {
				continue
			}
			seen[f] = true
			filters = append(filters, f)
		}
		return filters
	}
	addr := addrs[0]
	if addr.IP == nil || (addr.IP.IsUnspecified() && addr.IP.To4() == nil) {
		return []string{
			fmt.Sprintf("local=0.0.0.0:%d,handshake=0:3", addr.Port),
			fmt.Sprintf("local=[::]:%d,handshake=0:3", addr.Port),
		}
	}
	// handshake is interval:retry; interval zero makes this side passive,
	// so it answers connections but never opens one.
	return []string{fmt.Sprintf("local=%s:%d,handshake=0:3", filterHost(addr.IP), addr.Port)}
}

// filterHost renders an IP the way Mimic's filter syntax expects, bracketing
// IPv6 so the port stays unambiguous.
func filterHost(ip net.IP) string {
	if ip == nil || ip.IsUnspecified() {
		if ip != nil && ip.To4() == nil {
			return "[::]"
		}
		return "0.0.0.0"
	}
	if ip.To4() == nil {
		return "[" + ip.String() + "]"
	}
	return ip.String()
}

// resolveInterface finds the interface carrying traffic for addr, falling back
// to the default route's when there is nothing to route towards.
func resolveInterface(configured string, role Role, addr *net.UDPAddr) (string, error) {
	if configured != "" {
		if _, err := net.InterfaceByName(configured); err != nil {
			return "", fmt.Errorf("interface %q not found: %w", configured, err)
		}
		return configured, nil
	}
	probe := addr
	if role == RoleServer || addr.IP == nil || addr.IP.IsUnspecified() {
		// Assume the interface reaching the internet is the one facing peers.
		probe = &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53}
	}
	local, err := localAddrTowards(probe)
	if err != nil {
		return "", fmt.Errorf("failed to determine the interface for mimic, set it explicitly: %w", err)
	}
	iface, err := interfaceWithAddr(local)
	if err != nil {
		return "", fmt.Errorf("failed to determine the interface for mimic, set it explicitly: %w", err)
	}
	return iface, nil
}

// localAddrTowards returns the source address the kernel would pick for addr.
// The socket is never used, so nothing is sent.
func localAddrTowards(addr *net.UDPAddr) (net.IP, error) {
	c, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP, nil
}

func interfaceWithAddr(ip net.IP) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, ifi := range ifaces {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return ifi.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no interface holds address %s", ip)
}
