# 用 Hysteria 承载 VXLAN

两端各开一张 MTU 1600 的原始 TUN，VXLAN 跑在这两张网卡之间。QUIC 仍走原来的物理网络，物理网卡保持 1500。代理用的 `tun` 不参与这条链路。

这条链路一次只服务一个客户端。IP 包最大 1600 字节。内层 MTU 1500 时，外层大约 1550 字节，落在 1600 以内，内核不会再分片。

## 拓扑

```
客户端 vx0 10.201.0.2/24
        |
客户端 hytun0 10.200.0.2/30  MTU 1600
        |
        QUIC datagram
        |
服务端 hytun0 10.200.0.1/30  MTU 1600
        |
服务端 vx0 10.201.0.1/24
```

VXLAN 的 `local` / `remote` 使用两端 `hytun0` 的地址。`/30` 自带直连路由，不需要打开 IP 转发，也不需要把默认路由指进隧道。服务器的公网地址在 `/30` 之外，QUIC 不会绕回隧道。

## 两端都要启用

`l3tun` 写在客户端，客户端才会在认证请求里带上 `Hysteria-L3`。服务端同样写了 `l3tun`，才会在认证响应里同意。缺任意一侧，这张网卡不会通。

旧版 Hysteria 不认识这种 datagram，会直接丢掉。两端都要跑带这个功能的程序。

创建 TUN 和 VXLAN 需要 root，或者 `CAP_NET_ADMIN`。

## 配置

其余监听、认证、TLS、带宽配置保持原样。下面只列出隧道段。

客户端：

```yaml
l3tun:
  name: hytun0
  mtu: 1600
  address: 10.200.0.2/30
  peer: 10.200.0.1
```

服务端：

```yaml
l3tun:
  name: hytun0
  mtu: 1600
  address: 10.200.0.1/30
  peer: 10.200.0.2
```

| 字段 | 含义 |
| --- | --- |
| `name` | 本机 TUN 名称，不能和已有网卡重名 |
| `mtu` | 省略时为 1600，不能大于 1600 |
| `address` | 本端地址，写成前缀 |
| `peer` | 对端地址，必须和 `address` 同一 IP 版本 |

程序会创建网卡并配置 `address`。不要再手动给 `hytun0` 加同一个地址。

## 建立 VXLAN

Hysteria 起来、`hytun0` 出现之后再加 VXLAN。`4789` 是 VXLAN 自己的 UDP 端口，包在隧道里面，公网防火墙不用放行它。

客户端：

```bash
ip link add vx0 type vxlan id 100 local 10.200.0.2 remote 10.200.0.1 dstport 4789
ip link set vx0 mtu 1500
ip addr add 10.201.0.2/24 dev vx0
ip link set vx0 up
```

服务端：

```bash
ip link add vx0 type vxlan id 100 local 10.200.0.1 remote 10.200.0.2 dstport 4789
ip link set vx0 mtu 1500
ip addr add 10.201.0.1/24 dev vx0
ip link set vx0 up
```

`10.201.0.0/24` 是 VXLAN 内层网络，按实际网段替换。内层 MTU 保持 1500。

## 验证

在客户端确认一颗不允许分片的大包能通过内层：

```bash
ping -M do -s 1472 -c 3 10.201.0.1
```

1472 字节的 ICMP 载荷加上内层 IP 和以太网头，外层大约 1550 字节。通了，说明 1600 的隧道装得下。

并发吞吐：

```bash
# 服务端
iperf3 -s -B 10.201.0.1

# 客户端
iperf3 -c 10.201.0.1 -P 4
iperf3 -c 10.201.0.1 -u -b 0 -P 4
```

重启服务端后，客户端的 L3 连接会自己重连，`hytun0` 保持不动。VXLAN 会随着内层流量恢复。

## 传送方式

一颗 IP 包先整包放进一条 QUIC datagram。路径装不下时，按当时的载荷上限切成均匀的几片。1600 字节在常见的 1200 上限下是两片，每片约 800 字节。

多颗包的分片可以交错到达，按 32 位包序号重组。任一碎片丢失，整颗包作废，不重传。内层 TCP 自己重传。重组等待超过 200 毫秒也会丢弃。

服务端只保留最近一次认证、并且请求了 L3 的连接。没有对端时，从本机 TUN 读到的包直接丢弃。写入本机 TUN 之前，会核对 IP 源地址等于配置的 `peer`。

流量计入现有的 `TrafficLogger`，方向和 UDP 代理一致。
