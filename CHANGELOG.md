# Changelog

## 1.3.3

- Fix a bug that made UDP unusable when using `socks5_outbound`
- Set the default value of `retry_interval` to 1 to prevent the client from retrying too often when errors occur
- Prompt error if both acme and local cert file are specified in client config
- Updated quic-go to v0.32.0, performance improvements

## 1.3.2

- Fix a bug where some malformed UDP packets would cause the server to crash
- Fix a bug where the server did not have a timeout for SOCKS5 outbound connections
- Add build variants: amd64-avx, armv5, mipsle-sf, windows/arm64

## 1.3.1

- New `fast_open` option for client to reduce RTT when dialing TCP connections
- Fix a bug where the HTTP proxy would not close connections properly
- Minor performance improvements here and there

## 1.3.0

- Connection migration: clients can now seamlessly switch between networks without losing their connection to the server
- Dynamic port hopping: see https://hysteria.network/docs/port-hopping/ for more information

## 1.2.2

- Fix a bug where the client would crash for IPv6 UDP requests in TProxy mode.
- Fix a bug where the client did not release old UDP sockets when reconnecting.
- Fix a bug where using DoT (DNS over TLS) as resolver would cause the client/server to crash.
- Add `quit_on_disconnect`, `handshake_timeout`, `idle_timeout` options to client config.
- Drop server's legacy protocol (v2) support.
- Updated quic-go to v0.30.0, small performance improvements.

## 1.2.1

- Fix a bug that caused DNS failure when using domain names in the "resolver" option
- Fix a bug where errors in HTTP proxy mode were not logged
- Fix a bug where WeChat protocol was not working properly when obfuscation was not enabled
- New TCP buffer options for tun mode (`tcp_sndbuf`, `tcp_rcvbuf`, `tcp_autotuning`)

## 1.2.0

- Reworked TUN mode
- DoT/DoH/DoQ support for resolver
- IP masking (anonymization)
- FreeBSD builds

## 1.1.0

- Super major CPU performance improvements (~30% to several times faster, depending on the circumstances) by optimizing several data structures in quic-go (changes upstreamed)

## 1.0.5

- `bind_outbound` server option for binding outbound connections to a specific address or interface
- TCP Redirect mode (for Linux)

## 1.0.4

- ~10% CPU usage reduction
- Improve performance when packet loss is high
- New ACL syntax to support protocol/port

## 1.0.3

- New string-based speed (up/down) options
- Server SOCKS5 outbound domain pass-through
- Linux s390x build
- Updated quic-go to v0.27.0

## 1.0.2

- Added an option for DNS resolution preference `resolve_preference`

## 1.0.1

- Fix server SOCKS5 outbound bug
- Fix incorrect UDP fragmentation handling

## 1.0.0

- Protocol v3: UDP fragmentation support
- Fix SOCKS5 UDP timeout issue
- SOCKS5 outbound support

## 0.9.7

- CLI improvements (cobra)
- Fix broken UDP TProxy mode
- Re-enable PMTUD on Windows & Linux

## 0.9.6

- Disable quic-go PMTUD due to broken implementation
- Fix zero initMaxDatagramSize in brutal CC
- Client retry

## 0.9.5

- Client connect & disconnect log
- Warning when no auth or obfs is set
- Multi-password & cmd auth support

## 0.9.4

- fsnotify-based auto keypair reloading
- ACL country code support

## 0.9.3

- CC optimizations
- Set buffer correctly for faketcp mode
- "wechat-video" protocol

## 0.9.2

- Updated quic-go to v0.24.0
- Reduced obfs overhead by reusing buffers

## 0.9.1

- faketcp implementation
- DNS `resolver` option in config

## 0.9.0

- Auto keypair reloading
- SOCKS5 listen address no longer needs a specific IP
- Multi-relay support
- IPv6 only mode for server

## 0.8.6

- Added an option for customizing ALPN `alpn`
- Removed ACL support from TPROXY & TUN modes

## 0.8.5

- Added an option to disable MTU discovery `disable_mtu_discovery`
