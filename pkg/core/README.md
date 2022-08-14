# A pluggable transport implementation based on Hysteria

## Hysteria
[Hysteria](https://github.com/HyNetwork/hysteria) uses a custom version of QUIC protocol ([RFC 9000 - QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000.html)):

* a custom congestion control ([RFC 9002 - QUIC Loss Detection and Congestion Control](https://www.rfc-editor.org/rfc/rfc9002.html))
* tweaked QUIC parameters
* an obfuscation layer
* non-standard transports (e.g. [faketcp](https://github.com/wangyu-/udp2raw))

## Usage

## Implementation

The implementation uses [Pluggable Transport Specification v3.0 - Go Transport API](https://github.com/Pluggable-Transports/Pluggable-Transports-spec/blob/main/releases/PTSpecV3.0/Pluggable%20Transport%20Specification%20v3.0%20-%20Go%20Transport%20API%20v3.0.md)