// Package mimic runs Mimic (https://github.com/hack3ric/mimic) as a child
// process for the lifetime of a Hysteria process.
//
// Mimic disguises UDP as TCP by rewriting packets in the kernel, transparently
// to the socket. We derive its filter from the address Hysteria already knows,
// so users don't have to configure it separately. Installing it is still up to
// them: its eBPF programs need its kernel module loaded.
package mimic

type Config struct {
	Enabled bool
	// Interface to attach to. Derived from the route to the peer when empty.
	Interface string
	// XDPMode forces "native" or "skb". Empty lets Mimic decide, which is
	// usually right; some drivers misbehave in native mode and need "skb".
	XDPMode string
	// Path to the mimic executable. Looked up in PATH when empty.
	Path string
	// ExtraArgs is passed through verbatim, for tuning Mimic has no Hysteria
	// equivalent of (padding, handshake and keepalive parameters).
	ExtraArgs []string
}

// Role determines which side of the connection we are, which decides both the
// filter's origin and whether this end opens the fake TCP connection.
type Role int

const (
	RoleClient Role = iota
	RoleServer
)
