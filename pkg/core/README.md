# A pluggable transport implementation based on Hysteria

## Hysteria
[Hysteria](https://github.com/HyNetwork/hysteria) uses a custom version of QUIC protocol ([RFC 9000 - QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000.html)):

* a custom congestion control ([RFC 9002 - QUIC Loss Detection and Congestion Control](https://www.rfc-editor.org/rfc/rfc9002.html))
* tweaked QUIC parameters
* an obfuscation layer
* non-standard transports (e.g. [faketcp](https://github.com/wangyu-/udp2raw))

## Usage

* Follow [Custom CA](https://hysteria.network/docs/custom-ca/) doc to generate certificates
* See [server side implementation example](https://github.com/apernet/hysteria/pull/340/files#diff-8a9b6ccee2487fc2b424d9f4b3cad2ebde2cc27b1cf1aa078e0de084872edbaaR62-R155) in the `transport_test.go` file
* See [client side implementation example](https://github.com/apernet/hysteria/pull/340/files#diff-8a9b6ccee2487fc2b424d9f4b3cad2ebde2cc27b1cf1aa078e0de084872edbaaR157-R229) in the `transport_test.go` file

## Implementation

The implementation uses [Pluggable Transport Specification v3.0 - Go Transport API](https://github.com/Pluggable-Transports/Pluggable-Transports-spec/blob/main/releases/PTSpecV3.0/Pluggable%20Transport%20Specification%20v3.0%20-%20Go%20Transport%20API%20v3.0.md)