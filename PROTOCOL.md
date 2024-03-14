# Hysteria 2 Protocol Specification

Hysteria is a TCP & UDP proxy based on QUIC, designed for speed, security and censorship resistance. This document describes the protocol used by Hysteria starting with version 2.0.0, sometimes internally referred to as the "v4" protocol. From here on, we will call it "the protocol" or "the Hysteria protocol".

## Requirements Language

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

## Underlying Protocol & Wire Format

The Hysteria protocol MUST be implemented on top of the standard QUIC transport protocol [RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000) with [Unreliable Datagram Extension](https://datatracker.ietf.org/doc/rfc9221/).

All multibyte numbers use Big Endian format.

All variable-length integers ("varints") are encoded/decoded as defined in QUIC (RFC 9000).

## Authentication & HTTP/3 masquerading

One of the key features of the Hysteria protocol is that to a third party without proper authentication credentials (whether it's a middleman or an active prober), a Hysteria proxy server behaves just like a standard HTTP/3 web server. Additionally, the encrypted traffic between the client and the server appears indistinguishable from normal HTTP/3 traffic.

Therefore, a Hysteria server MUST implement an HTTP/3 server (as defined by [RFC 9114](https://datatracker.ietf.org/doc/rfc9114/)) and handle HTTP requests as any standard web server would. To prevent active probers from detecting common response patterns in Hysteria servers, implementations SHOULD advise users to either host actual content or set it up as a reverse proxy for other sites.

An actual Hysteria client, upon connection, MUST send the following HTTP/3 request to the server:

```
:method: POST
:path: /auth
:host: hysteria
Hysteria-Auth: [string]
Hysteria-CC-RX: [uint]
Hysteria-Padding: [string]
```

`Hysteria-Auth`: Authentication credentials.

`Hysteria-CC-RX`: Client's maximum receive rate in bytes per second. A value of 0 indicates unknown.

`Hysteria-Padding`: A random padding string of variable length.

The Hysteria server MUST identify this special request, and, instead of attempting to serve content or forwarding it to an upstream site, it MUST authenticate the client using the provided information. If authentication is successful, the server MUST send the following response (HTTP status code 233):

```
:status: 233 HyOK
Hysteria-UDP: [true/false]
Hysteria-CC-RX: [uint/"auto"]
Hysteria-Padding: [string]
```

`Hysteria-UDP`: Whether the server supports UDP relay.

`Hysteria-CC-RX`: Server's maximum receive rate in bytes per second. A value of 0 indicates unlimited; "auto" indicates the server refuses to provide a value and ask the client to use congestion control to determine the rate on its own.

`Hysteria-Padding`: A random padding string of variable length.

See the Congestion Control section for more information on how to use the `Hysteria-CC-RX` values.

`Hysteria-Padding` is optional and is only intended to obfuscate the request/response pattern. It SHOULD be ignored by both sides.

If authentication fails, the server MUST either act like a standard web server that does not understand the request, or in the case of being a reverse proxy, forward the request to the upstream site and return the response to the client.

The client MUST check the status code to determine if the authentication was successful. If the status code is anything other than 233, the client MUST consider authentication to have failed and disconnect from the server.

After (and only after) a client passes authentication, the server MUST consider this QUIC connection to be a Hysteria proxy connection. It MUST then start processing proxy requests from the client as described in the next section.

## Proxy Requests

### TCP

For each TCP connection, the client MUST create a new QUIC bidirectional stream and send the following TCPRequest message:

```
[varint] 0x401 (TCPRequest ID)
[varint] Address length
[bytes] Address string (host:port)
[varint] Padding length
[bytes] Random padding
```

The server MUST respond with a TCPResponse message:

```
[uint8] Status (0x00 = OK, 0x01 = Error)
[varint] Message length
[bytes] Message string
[varint] Padding length
[bytes] Random padding
```

If the status is OK, the server MUST then begin forwarding data between the client and the specified TCP address until either side closes the connection. If the status is Error, the server MUST close the QUIC stream.

### UDP

UDP packets MUST be encapsulated in the following UDPMessage format and sent over QUIC's unreliable datagram (for both client-to-server and server-to-client):

```
[uint32] Session ID
[uint16] Packet ID
[uint8] Fragment ID
[uint8] Fragment count
[varint] Address length
[bytes] Address string (host:port)
[bytes] Payload
```

The client MUST use a unique Session ID for each UDP session. The server SHOULD assign a unique UDP port to each Session ID, unless it has another mechanism to differentiate packets from different sessions (e.g., symmetric NAT, varying outbound IP addresses, etc.).

The protocol does not provide an explicit way to close a UDP session. While a client can retain and reuse a Session ID indefinitely, the server SHOULD release and reassign the port associated with the Session ID after a period of inactivity or some other criteria. If the client sends a UDP packet to a Session ID that is no longer recognized by the server, the server MUST treat it as a new session and assign a new port.

If a server does not support UDP relay, it SHOULD silently discard all UDP messages received from the client.

#### Fragmentation

Due to the limit imposed by QUIC's unreliable datagram channel, any UDP packet that exceeds QUIC's maximum datagram size MUST either be fragmented or discarded.

For fragmented packets, each fragment MUST carry the same unique Packet ID. The Fragment ID, starting from 0, indicates the index out of the total Fragment Count. Both the server and client MUST wait for all fragments of a fragmented packet to arrive before processing them. If one or more fragments of a packet are lost, the entire packet MUST be discarded.

For packets that are not fragmented, the Fragment Count MUST be set to 1. In this case, the values of Packet ID and Fragment ID are irrelevant.

## Congestion Control

A unique feature of Hysteria is the ability to set the tx/rx (upload/download) rate on the client side. During authentication, the client sends its rx rate to the server via the `Hysteria-CC-RX` header. The server can use this to determine its transmission rate to the client, and vice versa by returning its rx rate to the client through the same header.

Three special cases are:

- If the client sends 0, it doesn't know its own rx rate. The server MUST use a congestion control algorithm (e.g., BBR, Cubic) to adjust its transmission rate.
- If the server responds with 0, it has no bandwidth limit. The client MAY transmit at any rate it wants.
- If the server responds with "auto", it chooses not to specify a rate. The client MUST use a congestion control algorithm to adjust its transmission rate.

## "Salamander" Obfuscation

The Hysteria protocol supports an optional obfuscation layer codenamed "Salamander".

"Salamander" encapsulates all QUIC packets in the following format:

```
[8 bytes] Salt
[bytes] Payload
```

For each QUIC packet, the obfuscator MUST calculate the BLAKE2b-256 hash of a randomly generated 8-byte salt appended to a user-provided pre-shared key.

```
hash = BLAKE2b-256(key + salt)
```

The hash is then used to obfuscate the payload using the following algorithm:

```
for i in range(0, len(payload)):
    payload[i] ^= hash[i % 32]
```

The deobfuscator MUST use the same algorithms to calculate the salted hash and deobfuscate the payload. Any invalid packet MUST be discarded.
