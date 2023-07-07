# Hysteria 2 Prototype

> **Warning**
> The code on this branch is a work-in-progress prototype of what will become Hysteria 2.0. It is currently very
> unfinished, and unless you know what you are doing, you should stick with the stable 1.x releases for now.

> **警告**
> 此分支的代码是 Hysteria 2.0 的原型，目前仍在开发中，完成度十分有限。除非你十分确定自己在做什么，否则请继续使用稳定的 1.x
> 版本。

## Build (编译)

Use the environment variable `HY_APP_PLATFORMS` to control which platforms to build for. For
example: `"windows/amd64,linux/amd64,linux/arm"`

用环境变量 `HY_APP_PLATFORMS` 来控制编译哪些平台的可执行文件。例如：`"windows/amd64,linux/amd64,linux/arm"`

```bash
python ./hyperbole.py build
```

Builds will be placed in `./build` (编译输出在 `./build` 目录下)

## Usage (使用)

### Server

```bash
./hysteria server -c config.yaml
```

[Example sever config (示例服务器配置)](app/server.example.yaml)

### Client

```bash
./hysteria client -c config.yaml
```

[Example client config (示例客户端配置)](app/client.example.yaml)

## Logging (日志)

The following environment variables for controlling logging are supported:

- `HYSTERIA_LOG_LEVEL` - supported values are `debug`, `info`, `warn`, `error`

- `HYSTERIA_LOG_FORMAT` - supported values are `console`, `json`

支持通过以下环境变量来控制日志：

- `HYSTERIA_LOG_LEVEL` - 支持的值有 `debug`, `info`, `warn`, `error`

- `HYSTERIA_LOG_FORMAT` - 支持的值有 `console`, `json`

## Test HTTP/3 masquerading (测试 HTTP/3 伪装)

```bash
chrome --origin-to-force-quic-on=example.com:443
```

Then visit `https://example.com/` in Chrome.