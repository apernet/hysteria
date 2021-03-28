# ACL 文件格式

ACL 文件描述如何处理传入请求。服务器和客户端都支持 ACL，并且遵循相同的语法。

```
处理方式 条件类型 条件 参数
```

例子：

```
direct domain evil.corp
proxy domain-suffix google.com
block ip 1.2.3.4
hijack cidr 192.168.1.1/24 127.0.0.1

direct all
```

一个直连所有中国 IP 的规则和 Python 生成脚本 [在这里](docs/acl)。

Hysteria 根据文件中第一个匹配到规则对每个请求进行操作。当没有匹配时默认的行为是代理连接。可以通过在文件的末尾添加一个规则加上条件 "all" 来设置默认行为。

4 种处理方式:

`direct` - 直接连接到目标服务器，不经过代理

`proxy` - 通过代理连接到目标服务器（仅在客户端上可用）

`block` - 拒绝连接建立

`hijack` - 把连接劫持到另一个目的地 （必须在参数中指定）

5 种条件类型:

`domain` - 匹配特定的域名（不匹配子域名！例如：`apple.com` 不匹配 `cdn.apple.com`）

`domain-suffix` - 匹配域名后缀（包含子域名，但 `apple.com` 仍不会匹配 `fakeapple.com`）

`cidr` - IPv4 / IPv6 CIDR

`ip` - IPv4 / IPv6 地址

`all` - 匹配所有地址 （通常放在文件尾作为默认规则）

对于域名请求，Hysteria 将尝试解析域名并同时匹配域名规则和 IP 规则。换句话说，IP 规则能覆盖到所有连接，无论客户端是用 IP 还是域名请求。