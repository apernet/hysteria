## 关于 Dockerfile

hysteria 的 docker 镜像基于 **alpine** 系统，这意味着如果您在容器里运行一些依赖于 glibc
的自定义程序可能会失败。

默认情况下容器内安装了 **`bash`** 用于调试目的，安装的 **`tzdata`** 用于提供容器的时区信息；
为了保证 ACME 等连其他网站时 SSL 证书信任还安装了 **`ca-certificates`**；除此之外容器内不包含
任何非标准 alpine 系统的其他工具。

hysteria 二进制可执行文件默认被安装到 `/usr/local/bin/hysteria`，同时容器的 **ENTRYPOINT**
被设置为**执行 `hysteria` 命令**；这意味着在不进行覆盖的情况下容器启动后首先将执行 `hysteria`
命令。

## 如何使用本镜像?

### 标准 Docker 用户

您可以将配置文件挂载到容器内的任何位置然后使用它。

在下面的命令中我们假设将 **`/root/hysteria.json`** 配置文件挂载为容器内的 **`/etc/hysteria.json`** 文件。

```sh
# Please replace `/root/hysteria.json` with the actual configuration file location
docker run -dt --name hysteria \
    -v /root/hysteria.json:/etc/hysteria.json \
    tobyxdd/hysteria -config /etc/hysteria.json server
```

### Docker Compose 用户 

首先您需要创建一个任意名称的目录，然后将项目内的 [docker-compise.yaml](https://raw.githubusercontent.com/HyNetwork/hysteria/master/docker-compose.yaml) 文件复制到该目录；
最后创建自己的配置文件并启动即可。

```sh
# Create dir
mkdir hysteria && cd hysteria

# Download the docker-compose example config
wget https://raw.githubusercontent.com/HyNetwork/hysteria/master/docker-compose.yaml

# Create your config
cat <<EOF > hysteria.json
{
  "listen": ":36712",
  "acme": {
    "domains": [
      "your.domain.com"
    ],
    "email": "hacker@gmail.com"
  },
  "obfs": "fuck me till the daylight",
  "up_mbps": 100,
  "down_mbps": 100
}
EOF

# Start container
docker-compose up -d
```

