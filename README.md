# ![Hysteria 2](logo.svg)

# 支持对接Xboard/V2board面板的Hysteria2后端

### 项目说明
本项目基于hysteria官方内核二次开发，添加了从 Xboard/V2board 获取节点信息、用户鉴权信息与上报用户流量的功能。
性能方面已经由hysteria2内核作者亲自指导优化过了。


准备工作：默认在root目录下开始。
配置ssl证书，使用acme配置证书要占用80端口，CentOS自行把`apt`改成`yum`。
```
apt install -y vim openssl curl socat && mkdir hysteria
```
```
curl https://get.acme.sh | sh -s email=rebecca554owen@gmail.com
```
```
~/.acme.sh/acme.sh --upgrade --auto-upgrade
```
可选：切换申请letsencrypt的证书，`~/.acme.sh/acme.sh --set-default-ca --server letsencrypt`

中间的 example.com 换成你解析到 vps 的域名。可选：后面的 example.com 可以不用自定义，待会docker-compose.yml就不用改了。
```
~/.acme.sh/acme.sh --issue -d example.com --standalone
~/.acme.sh/acme.sh --install-cert -d example.com --key-file /root/hysteria/example.com.key
~/.acme.sh/acme.sh --install-cert -d example.com --fullchain-file /root/hysteria/example.com.crt
```
安装docker，docker compose
```
curl -fsSL https://get.docker.com | bash -s docker
systemctl start docker
systemctl enable docker
```
修改 docker-compose.yml, server.yaml 配置文件。  
Finalshell 注意：直接新建文件，复制粘贴过去，用终端粘贴不了符号。
```
cd hysteria
```
```
vim docker-compose.yml
```
---配置文件docker-compose.yml参考
```
version: "3.9"
services:
  hysteria:
    image: ghcr.io/wo5zhidaoa/hysteria:latest
    container_name: hysteria
    restart: always
    network_mode: "host"
    volumes:
      - ./server.yaml:/etc/hysteria/server.yaml         # ./表示当前目录，其他路径就改成如 /root/hysteria/server.yaml ；冒号前面是真实路径，后面是挂载到容器内的路径以及名称。
      - ./example.com.crt:/etc/hysteria/example.com.crt # 冒号前面的 example.com 换成你自己的后端vps绑定域名。
      - ./example.com.key:/etc/hysteria/example.com.key # 冒号后面的保留 example.com ，这样server.yaml 就不用改tls参数了。
    command: ["server", "-c", "/etc/hysteria/server.yaml"]
```
---配置文件server.yaml参考
```
vim server.yaml
```
```
v2board:
  apiHost: https://example.com # v2board面板域名
  apiKey: 123456789 # 通讯密钥
  nodeID: 1 # 节点id
tls:
  type: tls
  cert: /etc/hysteria/example.com.crt #
  key: /etc/hysteria/example.com.key  #
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
更新，在 hysteria 目录执行。
```
docker compose pull && docker compose up -d
```
