# Changelog

## 0.8.5

- Added an option to disable MTU discovery `disable_mtu_discovery`

## 0.8.6

- Added an option for customizing ALPN `alpn`
- Removed ACL support from TPROXY & TUN modes

## 0.9.0

- Auto keypair reloading
- SOCKS5 listen address no longer needs a specific IP
- Multi-relay support
- IPv6 only mode for server

## 0.9.1

- faketcp implementation
- DNS `resolver` option in config

## 0.9.2

- Updated quic-go to v0.24.0
- Reduced obfs overhead by reusing buffers

## 0.9.3

- CC optimizations
- Set buffer correctly for faketcp mode
- "wechat-video" protocol

## 0.9.4

- fsnotify-based auto keypair reloading
- ACL country code support