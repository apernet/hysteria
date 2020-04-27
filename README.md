# ![Logo](docs/logos/readme.png)

[![License][1]][2] [![Release][3]][4] [![Telegram][5]][6]

[1]: https://img.shields.io/github/license/tobyxdd/hysteria?style=flat-square
[2]: LICENSE.md
[3]: https://img.shields.io/github/v/release/tobyxdd/hysteria?style=flat-square
[4]: https://github.com/tobyxdd/hysteria/releases
[5]: https://patrolavia.github.io/telegram-badge/chat.png
[6]: https://t.me/hysteria_github

[中文 README](README.zh.md)

Hysteria is a set of relay & proxy utilities that are specifically optimized for harsh network environments (commonly seen in connecting to overseas servers from China). It's based on a modified version of the QUIC protocol, and can be considered a sequel to my previous (abandoned) project https://github.com/dragonite-network/dragonite-java

## Quick Start

(See the [advanced usage section](#advanced-usage) for the exact meaning of each argument)

### Proxy

Server:
```
./cmd_linux_amd64 proxy server -listen :36712 -cert example.crt -key example.key -obfs BlueberryFaygo
```
A TLS certificate (not necessarily issued by a trusted CA) is required on the server side. If you are using a self-issued certificate, use `-ca` to specify your own CA file on clients, or `-insecure` to ignore all certificate errors (not recommended)

Client:
```
./cmd_linux_amd64 proxy client -server example.com:36712 -socks5-addr localhost:1080 -up-mbps 10 -down-mbps 50 -obfs BlueberryFaygo
```
This will start a SOCKS5 proxy server on the client's localhost TCP 1080 available for use by other programs.

`-up-mbps 10 -down-mbps 50` tells the server that your bandwidth is 50 Mbps down, 10 Mbps up. Properly setting the client's upload and download speeds based on your network conditions is essential for it to work at optimal performance!

### Relay

Suppose you have a TCP program on your server at `localhost:8080` that you want to forward.

Server:
```
./cmd_linux_amd64 relay server -listen :36712 -remote localhost:8080 -cert example.crt -key example.key
```

Client:
```
./cmd_linux_amd64 relay client -server example.com:36712 -listen localhost:8080 -up-mbps 10 -down-mbps 50
```
All connections to client's localhost TCP 8080 will pass through the relay and connect to the server's `localhost:8080`

Some users may attempt to forward other encrypted proxy protocols such as Shadowsocks with relay. While this totally works, it's not optimal from a performance standpoint - our protocol itself uses TLS, considering that the proxy protocols being forwarded are also encrypted, and the fact that users mainly use them for HTTPS connections nowadays, you are essentially doing triple encryption. If you need a proxy, use our proxy mode.

## Comparison

Proxy Client: Guangzhou, China Mobile Broadband 100 Mbps
 
Proxy Server: AWS US West Oregon (us-west-2)

![Bench1](docs/bench/bench1.png)

## Advanced usage

The command line program supports loading configurations from both JSON files and arguments. Use `-config` to specify a JSON file. Config loaded from it can also be overwritten or extended with command line arguments.

### Proxy server

| Description | JSON config field | CLI argument |
| --- | --- | --- |
| Server listen address | listen | -listen |
| Access control list | acl | -acl |
| TLS certificate file | cert | -cert |
| TLS key file | key | -key |
| Authentication file | auth | -auth |
| Max upload speed per client in Mbps | up_mbps | -up-mbps |
| Max download speed per client in Mbps | down_mbps | -down-mbps |
| Max receive window size per connection | recv_window_conn | -recv-window-conn |
| Max receive window size per client | recv_window_client | -recv-window-client |
| Max simultaneous connections allowed per client | max_conn_client | -max-conn-client |
| Obfuscation key | obfs | -obfs |

### Proxy client

| Description | JSON config field | CLI argument |
| --- | --- | --- |
| SOCKS5 listen address | socks5_addr | -socks5-addr |
| SOCKS5 connection timeout in seconds | socks5_timeout | -socks5-timeout |
| Access control list | acl | -acl |
| Server address | server | -server |
| Authentication username | username | -username |
| Authentication password | password | -password |
| Ignore TLS certificate errors | insecure | -insecure |
| Specify a trusted CA file | ca | -ca |
| Upload speed in Mbps | up_mbps | -up-mbps |
| Download speed in Mbps | down_mbps | -down-mbps |
| Max receive window size per connection | recv_window_conn | -recv-window-conn |
| Max receive window size | recv_window | -recv-window |
| Obfuscation key | obfs | -obfs |

#### About SOCKS5

Supports TCP (CONNECT) and UDP (ASSOCIATE) commands. BIND is not supported and is not planned to be supported.

#### About ACL

[ACL File Format](ACL.md)

#### About proxy authentication

Proxy supports username and password authentication (sent encrypted with TLS). If the server starts with an authentication file, it will check for the existence of the corresponding username and password in this file when each user connects. A valid authentication file is a text file with a pair of username and password per line (separated by a space). Example:
```
admin K2MfcwyZNJy3
shady_hacker smokeweed420

This line is invalid and will be ignored
```
Changes to the file take effect immediately while the server is running.

#### About obfuscation

To prevent firewalls from potentially detecting & blocking the protocol, a simple XOR-based packet obfuscation mechanism has been built in. Note that clients and servers with different obfuscation settings are not be able to communicate at all.

### Relay server

| Description | JSON config field | CLI argument |
| --- | --- | --- |
| Server listen address | listen | -listen |
| Remote relay address | remote | -remote |
| TLS certificate file | cert | -cert |
| TLS key file | key | -key |
| Max upload speed per client in Mbps | up_mbps | -up-mbps |
| Max download speed per client in Mbps | down_mbps | -down-mbps |
| Max receive window size per connection | recv_window_conn | -recv-window-conn |
| Max receive window size per client | recv_window_client | -recv-window-client |
| Max simultaneous connections allowed per client | max_conn_client | -max-conn-client |
| Obfuscation key | obfs | -obfs |

### Relay client

| Description | JSON config field | CLI argument |
| --- | --- | --- |
| TCP listen address | listen | -listen |
| Server address | server | -server |
| Client name presented to the server | name | -name |
| Ignore TLS certificate errors | insecure | -insecure |
| Specify a trusted CA file | ca | -ca |
| Upload speed in Mbps | up_mbps | -up-mbps |
| Download speed in Mbps | down_mbps | -down-mbps |
| Max receive window size per connection | recv_window_conn | -recv-window-conn |
| Max receive window size | recv_window | -recv-window |
| Obfuscation key | obfs | -obfs |
