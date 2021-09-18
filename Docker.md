## About Dockerfile

The hysteria docker image is based on the **alpine** system. This means that
**some glibc calls may not work if you run programs that depend on glibc in a container.**

By default, **bash** is installed in the docker container for debugging, **tzdata** is used to
provide container time zone configuration, and **ca-certificates** is used to ensure the 
trust of the ssl certificate chain; in addition, the docker container does not contain 
any tools other than the alpine standard system.

The hysteria binary is installed in `/usr/local/bin/hysteria`, and the **ENTRYPOINT**
of the docker container is set to **execute the `hysteria` command**; this means that
the `hysteria` command is always the first command.

## How to use docker image?

### For standard docker users

You can mount the configuration file to any location of the docker container and use it.

In the following commands, we assume that the **`/root/hysteria.json`** configuration
file is mounted to **`/etc/hysteria.json`**:

```sh
# Please replace `/root/hysteria.json` with the actual configuration file location
docker run -dt --name hysteria \
    -v /root/hysteria.json:/etc/hysteria.json \
    tobyxdd/hysteria -config /etc/hysteria.json server
```

### For docker-compose users

First, you need to create a directory with any name, and then copy [docker-compise.yaml](https://raw.githubusercontent.com/HyNetwork/hysteria/master/docker-compose.yaml) to 
that directory. Finally, create your configuration file and start it.

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



