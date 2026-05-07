# realm

UDP hole-punching framework with a small REST/SSE rendezvous service.

This package is intentionally **not coupled to the Hysteria protocol**. Hysteria is its first-party user, but the punch protocol, STUN discovery, and rendezvous client are protocol-agnostic and can be reused by **any UDP-based client/server protocol** (QUIC, WireGuard, etc.) to bring up a peer-to-peer UDP path between two NATted hosts.

The matching rendezvous service is at <https://github.com/apernet/hysteria-realm-server> and is also reusable.

## What it does

1. The **server** (the side that wants to be reachable) opens a UDP socket, asks STUN servers for its public address(es), and registers a *realm* (a name) with the rendezvous over HTTPS.
2. The **client** (the side that wants to connect) opens its own UDP socket, runs STUN, and asks the rendezvous to put it in touch with that realm.
3. The rendezvous returns the server's public addresses to the client and pushes the client's addresses to the server over an SSE event stream.
4. Both sides simultaneously send punch packets at each other on those addresses, opening a NAT pinhole.
5. Once a pinhole is open, you hand the same UDP socket to your protocol's normal handshake. The rendezvous is no longer involved.

The rendezvous **never relays application traffic**. It's an introduction service.

## Integration

The library is two roles. Wire them together however your application is structured.

### Server side (long-lived, accepting connections)

```go
import (
    "context"
    "net"
    "github.com/apernet/hysteria/extras/v2/realm"
)

ctx := context.Background()

// 1. Open the UDP socket your protocol will eventually serve on.
udp, _ := net.ListenUDP("udp", &net.UDPAddr{})

// 2. Wrap it. PunchPacketConn intercepts STUN responses and punch packets so
//    they don't reach your protocol's listener; everything else passes through.
pconn, _ := realm.NewPunchPacketConn(udp, 0)

// 3. Run STUN discovery to learn your public addresses.
localAddrs, _ := realm.DiscoverWithDemux(ctx, pconn, realm.STUNConfig{
    Servers: []string{"stun.nextcloud.com:3478"},
})

// 4. Spawn a ServerPuncher that handles incoming connect requests.
puncher, _ := realm.NewServerPuncher(ctx, pconn)

// 5. Register the realm with the rendezvous.
addr, _ := realm.ParseAddr("realm://YOUR-TOKEN@rendezvous.example.com/my-realm")
rc, _ := realm.NewClientFromAddr(addr, nil)
sess, _ := rc.Register(ctx, addr.RealmID, addrPortStrings(localAddrs))

// 6. Open the SSE stream and respond to each connect request.
stream, _ := rc.Events(ctx, addr.RealmID, sess.SessionID)
go func() {
    for {
        ev, err := stream.Next()
        if err != nil { return }
        // ev contains the client's addresses + punch metadata.
        peerAddrs, _ := parseAddrPorts(ev.Addresses)
        go puncher.Respond(ctx, /*attemptID*/ ev.Nonce,
            localAddrs, peerAddrs, ev.PunchMetadata, realm.PunchConfig{})
    }
}()

// 7. Heartbeat in the background to keep the realm registered.
go heartbeat(ctx, rc, addr.RealmID, sess.SessionID)

// 8. Hand pconn to your protocol's listener — it now sees only data packets.
yourProtocol.Serve(pconn)
```

### Client side (one-shot, dialing out)

```go
udp, _ := net.ListenUDP("udp", &net.UDPAddr{})

// 1. STUN discovery on the same socket.
localAddrs, _ := realm.Discover(ctx, udp, realm.STUNConfig{
    Servers: []string{"stun.nextcloud.com:3478"},
})

// 2. Fresh punch metadata (random nonce + obfs key).
meta, _ := realm.NewPunchMetadata()

// 3. Ask the rendezvous to put us in touch with the server.
addr, _ := realm.ParseAddr("realm://YOUR-TOKEN@rendezvous.example.com/my-realm")
rc, _ := realm.NewClientFromAddr(addr, nil)
resp, _ := rc.Connect(ctx, addr.RealmID, realm.ConnectRequest{
    Addresses:     addrPortStrings(localAddrs),
    PunchMetadata: meta,
})
peerAddrs, _ := parseAddrPorts(resp.Addresses)

// 4. Punch through. Returns the peer address that successfully responded.
result, _ := realm.Punch(ctx, udp, localAddrs, peerAddrs, meta, realm.PunchConfig{})

// 5. Hand the socket + result.PeerAddr to your protocol's dialer.
yourProtocol.Dial(udp, result.PeerAddr)
```

The client does **not** need `PunchPacketConn`. The punch is one-shot and complete before any application traffic flows.

## Things to know

- **STUN servers** are not part of this protocol. Pass any list you trust via `STUNConfig.Servers`. Default discovery uses the addresses your caller provides; there are no built-in defaults in this package.
- **NAT compatibility** — full-cone and (port-)restricted-cone NATs work reliably. Symmetric NATs sometimes work via heuristics in the punch engine, but cannot be guaranteed. Public-IP / no-NAT obviously works.
- **TLS for the rendezvous** is strongly recommended in production; use the `realm://` scheme. `realm+http://` exists for development and **should not** be used over the public internet.
- **Authentication** — the realm token is a shared bearer token between the server and rendezvous; it does not authenticate clients to the application. Your protocol must do its own authentication on top of the punched connection.

## Reusing the protocol from other languages

The on-wire pieces are small and straightforward:

- The **rendezvous protocol** is REST + SSE. Its full description is in the [rendezvous server README](https://github.com/apernet/hysteria-realm-server#api).
- The **STUN exchange** is plain RFC 5389 binding requests/responses over the same socket as application traffic. `stun.go` shows the demux: any datagram that begins with the STUN magic cookie is routed to STUN, everything else to the application.
- The **punch packet format** is in `punch.go` (`EncodePunchPacket` / `DecodePunchPacket`). It's a short fixed header plus an XOR-obfuscated body keyed by the per-session metadata. Match these byte-for-byte and your implementation will interoperate with any other compliant client/server.
