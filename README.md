# ![Hysteria 2](logo.svg)

# 支持对接V2board面板的Hysteria2后端

### 项目说明
本项目基于hysteria官方内核二次开发，添加了从v2b获取节点信息、用户鉴权信息与上报用户流量的功能。
性能方面已经由hysteria2内核作者亲自指导优化过了。

### TG交流群
欢迎加入交流群 [点击加入](https://t.me/+DcRt8AB2VbI2Yzc1)


### 示例配置
```
v2board:
  apiHost: https://面板地址
  apiKey: 面板节点密钥
  nodeID: 节点ID
tls:
  type: tls
  cert: /etc/hysteria/tls.crt
  key: /etc/hysteria/tls.key
auth:
  type: v2board
trafficStats:
  listen: 127.0.0.1:7653
acl: 
  inline: 
    - reject(10.0.0.0/8)
    - reject(172.16.0.0/12)
    - reject(192.168.0.0/16)
    - reject(127.0.0.0/8)
    - reject(fc00::/7)
```
> 其他配置完全与hysteria文档的一致，可以查看hysteria2官方文档 [点击查看](https://hysteria.network/zh/docs/getting-started/Installation/) 

### docker 仓库
```
docker pull ghcr.io/cedar2025/hysteria:v1.0.5
```
