# ![Hysteria 2](logo.svg)

# 支持对接Xboard/V2board面板的Hysteria2后端

### 项目说明
本项目基于hysteria官方内核二次开发，添加了从 Xboard/V2board 获取节点信息、用户鉴权信息与上报用户流量的功能。
性能方面已经由hysteria2内核作者亲自指导优化过了。

### TG交流群
欢迎加入交流群 [点击加入](https://t.me/+DcRt8AB2VbI2Yzc1)

准备工作：安装docker，docker compose
```
curl -fsSL https://get.docker.com | bash -s docker
sudo systemctl start docker
sudo systemctl enable docker
docker --version
docker compose version
```
下载并修改配置文件docker-compose.yml,server.yaml,包括前端信息和后端域名
```
git clone https://github.com/cedar2025/hysteria.git hysteria && cd hysteria
```
```
apt install vim -y && vim docker-compose.yml
```
---配置文件docker-compose.yml参考
```
version: "3.9"
services:
  hysteria:
    image: ghcr.io/cedar2025/hysteria:latest
    container_name: hysteria
    restart: always
    network_mode: "host"
    volumes:
      - ./server.yaml:/etc/hysteria/server.yaml         # 前面是真实路径，后面是挂载容器内的路径以及名称。
      - ./example.com.crt:/etc/hysteria/example.com.crt # ./表示当前目录，/etc/XrayR/证书目录/ 表示对应其他目录证书。
      - ./example.com.key:/etc/hysteria/example.com.key # example.com 换成你自己的后端vps绑定域名,可以共用 XrayR/V2bX 申请的证书
    command: ["server", "-c", "/etc/hysteria/server.yaml"]
```
---配置文件server.yaml参考
```
v2board:
  apiHost: https://example.com #v2board面板域名
  apiKey: 123456789 #通讯密钥
  nodeID: 1 #节点id
tls:
  type: tls
  cert: /etc/hysteria/example.com.crt #example.com换成你自己的后端vps绑定域名
  key: /etc/hysteria/example.com.key #example.com换成你自己的后端vps绑定域名
auth:
  type: v2board
trafficStats:
  listen: 127.0.0.1:7653
acl: 
  inline: 
    - reject(pincong.rocks) #acl规则自行查阅hysteria2文档
```
启动docker compose
```
docker compose up -d
```
查看日志：
```
docker logs -f hysteria
```
容器停止，更新，后台启动。
```
docker compose down && docker compose pull && docker compose up -d
```
