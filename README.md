# ![Logo](docs/logos/readme.png)

[![License][1]][2] [![Release][3]][4] [![Telegram][5]][6]

[1]: https://img.shields.io/github/license/tobyxdd/hysteria?style=flat-square

[2]: LICENSE.md

[3]: https://img.shields.io/github/v/release/tobyxdd/hysteria?style=flat-square

[4]: https://github.com/tobyxdd/hysteria/releases

[5]: https://img.shields.io/badge/chat-Telegram-blue?style=flat-square

[6]: https://t.me/hysteria_github

[中文 README](README.zh.md)

Hysteria is a TCP relay & SOCKS5/HTTP proxy tool optimized for networks of poor quality (e.g. satellite connections,
congested public Wi-Fi, connecting from China to servers abroad) powered by a custom version of QUIC protocol.

It is essentially a spiritual successor of my abandoned project https://github.com/dragonite-network/dragonite-java

## Installation

- Download pre-built binaries from https://github.com/tobyxdd/hysteria/releases
- Pull the image from Docker Hub: https://hub.docker.com/r/tobyxdd/hysteria
- Use our Arch Linux AUR: https://aur.archlinux.org/packages/hysteria/
- Build from source with `go build ./cmd`

## Quick Start

Note: This is only a bare-bones example to get the server and client running. Go to [Advanced usage](#advanced-usage)
for all the available options.

### Server

Create a `config.json` under the root directory of the program:

```json
{
  "listen": ":36712",
  "cert": "/home/ubuntu/my_cert.crt",
  "key": "/home/ubuntu/my_key.crt",
  "obfs": "AMOGUS",
  "up_mbps": 100,
  "down_mbps": 100
}
```

A TLS certificate is required on the server side. It does not have to be valid and trusted, but in that case the clients
need additional configuration.

The (optional) `obfs` option obfuscates the protocol using the provided password, so that it is not apparent that this
is Hysteria/QUIC, which could be useful for bypassing DPI blocking or QoS. If the passwords of the server and client do
not match, no connection can be established. Therefore, this can also serve as a simple password authentication. For
more advanced authentication schemes, see `auth` below.

`up_mbps` and `down_mbps` limit the maximum upload and download speed of the server for each client. Feel free to remove
them if you don't need.

To launch the server, simply run

```
./cmd_linux_amd64 server
```

If your config file is not named `config.json` or is in a different path, specify it with `-config`:

```
./cmd_linux_amd64 -config blah.json server
```

### Client

Same as the server side, create a `config.json` under the root directory of the program:

```json
{
  "server": "example.com:36712",
  "obfs": "AMOGUS",
  "up_mbps": 10,
  "down_mbps": 50,
  "socks5": {
    "listen": "127.0.0.1:1080"
  },
  "http": {
    "listen": "127.0.0.1:8080"
  },
  "relay": {
    "listen": "127.0.0.1:2222",
    "remote": "123.123.123.123:22"
  }
}
```

This config enables a SOCKS5 proxy (with both TCP & UDP support), an HTTP proxy, and a TCP relay to `123.123.123.123:22`
at the same time. Please modify or remove these entries according to your actual needs.

If your server certificate is not issued by a trusted CA, you need to specify the CA used
with `"ca": "/path/to/file.ca"` on the client or use `"insecure": true` to ignore all certificate errors (not
recommended).

`up_mbps` and `down_mbps` are mandatory on the client side. Try to fill in these values as accurately as possible
according to your network conditions, as they are crucial for Hysteria to work optimally.

Some users may attempt to forward other encrypted proxy protocols such as Shadowsocks with relay. While this technically
works, it's not optimal from a performance standpoint - Hysteria itself uses TLS, considering that the proxy protocol
being forwarded is also encrypted, and the fact that almost all sites are now using HTTPS, it essentially becomes triple
encryption. If you need a proxy, just use our proxy mode.

## Comparison

Proxy Client: Guangzhou, China Mobile Broadband 100 Mbps

Proxy Server: AWS US West Oregon (us-west-2)

![Bench1](docs/bench/bench1.png)

## Advanced usage

### Server

```json5
{
  "listen": ":36712", // Listen address
  "cert": "/home/ubuntu/my_cert.crt", // Cert file
  "key": "/home/ubuntu/my_key.crt", // Key file
  "up_mbps": 100, // Max upload Mbps per client
  "down_mbps": 100, // Max download Mbps per client
  "disable_udp": false, // Disable UDP support
  "acl": "my_list.acl", // See ACL below
  "obfs": "AMOGUS", // Obfuscation password
  "auth": { // Authentication
    "mode": "password", // Mode, supports "password" "none" and "external" for now
    "config": {
      "password": "yubiyubi"
    }
  },
  "prometheus_listen": ":8080", // Prometheus HTTP metrics server listen address (at /metrics)
  "recv_window_conn": 33554432, // QUIC stream receive window
  "recv_window_client": 67108864, // QUIC connection receive window
  "max_conn_client": 4096 // Max concurrent connections per client
}
```

#### External authentication integration

If you are a commercial proxy provider, you may want to connect Hysteria to your own authentication backend.

```json5
{
  // ...
  "auth": {
    "mode": "external",
    "config": {
      "http": "https://api.example.com/auth" // Both HTTP and HTTPS are supported
    }
  }
}
```

For the above config, Hysteria sends a POST request to `https://api.example.com/auth` upon each client's connection:

```json5
{
  "addr": "111.222.111.222:52731",
  "payload": "[BASE64]", // auth or auth_str of the client
  "send": 12500000, // Negotiated server send speed for this client (Bps)
  "recv": 12500000 // Negotiated server recv speed for this client (Bps)
}
```

The endpoint must return results with HTTP status code 200 (even if the authentication failed):

```json5
{
  "ok": false,
  "msg": "No idea who you are"
}
```

#### Prometheus Metrics

You can make Hysteria expose a Prometheus HTTP client endpoint for monitoring traffic usage with `prometheus_listen`.
If configured on port 8080, the endpoint would be at `http://example.com:8080/metrics`.

```text
hysteria_traffic_downlink_bytes_total{auth="55m95auW5oCq"} 122639
hysteria_traffic_downlink_bytes_total{auth="aGFja2VyISE="} 3.225058e+06

hysteria_traffic_uplink_bytes_total{auth="55m95auW5oCq"} 40710
hysteria_traffic_uplink_bytes_total{auth="aGFja2VyISE="} 37452
```

`auth` is the auth payload sent by the clients, encoded in Base64.

### Client

```json5
{
  "server": "example.com:36712", // Server address
  "up_mbps": 10, // Max upload Mbps
  "down_mbps": 50, // Max download Mbps
  "socks5": {
    "listen": "127.0.0.1:1080", // SOCKS5 listen address
    "timeout": 300, // TCP timeout in seconds
    "disable_udp": false, // Disable UDP support
    "user": "me", // SOCKS5 authentication username
    "password": "lmaolmao" // SOCKS5 authentication password
  },
  "http": {
    "listen": "127.0.0.1:8080", // HTTP listen address
    "timeout": 300, // TCP timeout in seconds
    "user": "me", // HTTP authentication username
    "password": "lmaolmao", // HTTP authentication password
    "cert": "/home/ubuntu/my_cert.crt", // Cert file (HTTPS proxy)
    "key": "/home/ubuntu/my_key.crt" // Key file (HTTPS proxy)
  },
  "relay": {
    "listen": "127.0.0.1:2222", // Relay listen address
    "remote": "123.123.123.123:22", // Relay remote address
    "timeout": 300 // TCP timeout in seconds
  },
  "acl": "my_list.acl", // See ACL below
  "obfs": "AMOGUS", // Obfuscation password
  "auth": "[BASE64]", // Authentication payload in Base64
  "auth_str": "yubiyubi", // Authentication payload in string, mutually exclusive with the option above
  "insecure": false, // Ignore all certificate errors 
  "ca": "my.ca", // Custom CA file
  "recv_window_conn": 33554432, // QUIC stream receive window
  "recv_window": 67108864 // QUIC connection receive window
}
```

## ACL

[ACL File Format](ACL.md)

## Logging

The program outputs `DEBUG` level, text format logs via stdout by default.

To change the logging level, use `LOGGING_LEVEL` environment variable. The available levels are `panic`, `fatal`
, `error`, `warn`, `info`, ` debug`, `trace`

To print JSON instead, set `LOGGING_FORMATTER` to `json`

To change the logging timestamp format, set `LOGGING_TIMESTAMP_FORMAT`