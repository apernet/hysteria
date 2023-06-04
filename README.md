# Hysteria 2 Prototype

> **Warning**
> The code on this branch is a work-in-progress prototype of what will become Hysteria 2.0. It is currently very unfinished, and unless you know what you are doing, you should stick with the stable 1.x releases for now. **The protocol is also subject to change, so we do not recommend third-party developers use this as a reference for the Hysteria 2 protocol at this time.**

> **警告**
> 此分支的代码是 Hysteria 2.0 的原型，目前仍在开发中，完成度十分有限。除非你十分确定自己在做什么，否则请继续使用稳定的 1.x 版本。**协议也可能会发生变化，因此我们不建议第三方开发者在目前使用此分支作为 Hysteria 2 协议的参考。**

## Build (编译)

Use the environment variable `HY_APP_PLATFORMS` to control which platforms to build for. For example: `"windows/amd64,linux/amd64,linux/arm"`

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

## Test HTTP/3 masquerading (测试 HTTP/3 伪装)

```bash
chrome --origin-to-force-quic-on=example.com:443
```

Then visit `https://example.com/` in Chrome.