# ![Logo](docs/logos/readme.png)

[![License][1]][2] [![Release][3]][4] [![Telegram][5]][6]

[1]: https://img.shields.io/github/license/tobyxdd/hysteria?style=flat-square
[2]: LICENSE.md
[3]: https://img.shields.io/github/v/release/tobyxdd/hysteria?style=flat-square
[4]: https://github.com/tobyxdd/hysteria/releases
[5]: https://img.shields.io/badge/chat-Telegram-blue?style=flat-square
[6]: https://t.me/hysteria_github

Hysteria 是专门针对恶劣网络环境（常见于在中国访问海外服务器）进行优化的连接转发和代理工具（即所谓的双边加速）。其基于修改版的 QUIC 协议，可以理解为是我此前弃坑的项目 https://github.com/dragonite-network/dragonite-java 的续作。

## 快速入门

关于每个参数具体的含义请见 [高级用法](#高级用法)

### 代理

服务端
```
./cmd_linux_amd64 proxy server -listen :36712 -cert example.crt -key example.key -obfs BlueberryFaygo
```
服务端需要一个 TLS 证书（不一定是由可信 CA 签发的有效证书）。如果你使用自签证书，请在客户端使用 `-ca` 指定你自己的 CA 文件，或者用 `-insecure` 忽略所有证书错误（不推荐）

客户端
```
./cmd_linux_amd64 proxy client -server example.com:36712 -socks5-addr localhost:1080 -up-mbps 10 -down-mbps 50 -obfs BlueberryFaygo
```
在客户端的本地 TCP 1080 上启动一个 SOCKS5 代理服务器供其他程序使用。

`-up-mbps 10 -down-mbps 50` 是告诉服务端你的下行速度为 50 Mbps, 上行 10 Mbps。根据实际网络条件正确设置客户端的上传和下载速度十分重要！

### 转发

假设你想转发服务端上 `localhost:8080` 的一个 TCP 协议程序。

服务端
```
./cmd_linux_amd64 relay server -listen :36712 -remote localhost:8080 -cert example.crt -key example.key
```

客户端
```
./cmd_linux_amd64 relay client -server example.com:36712 -listen localhost:8080 -up-mbps 10 -down-mbps 50
```
所有到客户端本地 TCP 8080 的 TCP 连接都将通过转发，到服务器连接那里的 `localhost:8080`

有些用户可能会尝试用这个功能转发其他加密代理协议，比如Shadowsocks。虽然这完全可行，但从性能的角度并不是最佳选择 - 我们的协议本身就有 TLS，转发的代理协议也是加密的，再加上用户用来访问 HTTPS 网站，等于做了三重加密。如果需要代理就用我们的代理模式。

## 对比

代理客户端：广州移动宽带 100M
 
代理服务端：AWS 美西 Oregon (us-west-2) (最差线路之一)

![Bench1](docs/bench/bench1.png)

## 高级用法

命令行程序支持从 JSON 文件和参数加载配置。使用 `-config` 指定一个JSON文件。从文件加载的配置也可以被命令行参数覆盖或进一步扩展。

### 代理 服务端

| 描述 | JSON 字段 | 命令行参数 |
| --- | --- | --- |
| 服务端监听地址 | listen | -listen |
| ACL 规则文件 | acl | -acl |
| TLS 证书文件 | cert | -cert |
| TLS 密钥文件 | key | -key |
| 用户名密码验证文件 | auth | -auth |
| 单客户端最大上传速度 Mbps | up_mbps | -up-mbps |
| 单客户端最大下载速度 Mbps | down_mbps | -down-mbps |
| 单连接最大接收窗口大小 | recv_window_conn | -recv-window-conn |
| 单客户端最大接收窗口大小 | recv_window_client | -recv-window-client |
| 单客户端最大连接数 | max_conn_client | -max-conn-client |
| 混淆密钥 | obfs | -obfs |

### 代理 客户端

| 描述 | JSON 字段 | 命令行参数 |
| --- | --- | --- |
| SOCKS5 监听地址 | socks5_addr | -socks5-addr |
| SOCKS5 超时时间（秒） | socks5_timeout | -socks5-timeout |
| ACL 规则文件 | acl | -acl |
| 服务端地址 | server | -server |
| 验证用户名 | username | -username |
| 验证密码 | password | -password |
| 忽略证书错误 | insecure | -insecure |
| 指定可信 CA 文件 | ca | -ca |
| 上传速度 Mbps | up_mbps | -up-mbps |
| 下载速度 Mbps | down_mbps | -down-mbps |
| 单连接最大接收窗口大小 | recv_window_conn | -recv-window-conn |
| 总最大接收窗口大小 | recv_window | -recv-window |
| 混淆密钥 | obfs | -obfs |

#### 关于 SOCKS5

支持 TCP (CONNECT) 和 UDP (ASSOCIATE)，不支持 BIND 也无计划支持。

#### 关于 ACL

[ACL 文件格式](ACL.zh.md)

#### 关于用户名密码验证

代理支持用户名和密码认证（经过 TLS 加密发送）。如果服务器启动时指定了一个验证文件，当每个用户连接时，服务器会检查该文件中是否存在相应的用户名和密码。验证文件是一个文本文件，每行有一对用户名和密码（用空格分割）。比如：
```
admin K2MfcwyZNJy3
shady_hacker smokeweed420

这行无效会被忽略
```
对文件的更改立即生效，即使服务端正在运行。

#### 关于混淆

为了防止各类防火墙今后可能检测并阻止协议，程序内置了简单的基于 XOR 的数据包混淆机制。注意客户端和服务器的混淆设置如果不同则完全无法通信。

### 转发 服务端

| 描述 | JSON 字段 | 命令行参数 |
| --- | --- | --- |
| 服务端监听地址 | listen | -listen |
| 转发目标地址 | remote | -remote |
| TLS 证书文件 | cert | -cert |
| TLS 密钥文件 | key | -key |
| 单客户端最大上传速度 Mbps | up_mbps | -up-mbps |
| 单客户端最大下载速度 Mbps | down_mbps | -down-mbps |
| 单连接最大接收窗口大小 | recv_window_conn | -recv-window-conn |
| 单客户端最大接收窗口大小 | recv_window_client | -recv-window-client |
| 单客户端最大连接数 | max_conn_client | -max-conn-client |
| 混淆密钥 | obfs | -obfs |

### 转发 客户端

| 描述 | JSON 字段 | 命令行参数 |
| --- | --- | --- |
| TCP 监听地址 | listen | -listen |
| 服务端地址 | server | -server |
| 客户端名称 | name | -name |
| 忽略证书错误 | insecure | -insecure |
| 指定可信 CA 文件 | ca | -ca |
| 上传速度 Mbps | up_mbps | -up-mbps |
| 下载速度 Mbps | down_mbps | -down-mbps |
| 单连接最大接收窗口大小 | recv_window_conn | -recv-window-conn |
| 总最大接收窗口大小 | recv_window | -recv-window |
| 混淆密钥 | obfs | -obfs |
