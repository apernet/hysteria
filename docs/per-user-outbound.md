# Per-user outbound routing

This fork adds the ability to route each authenticated user through a different
outbound (currently SOCKS5), and to change that mapping **at runtime** via the
existing trafficStats HTTP API — no restart, no dropped connections.

Users without a per-user outbound keep using the server's default outbound
(`outbounds` / ACL) exactly as before, so the feature is fully opt-in.

## How a user is identified

The map is keyed by the **auth id** returned by the server's authenticator —
the same id used by trafficStats and `/kick`:

- `auth.type: password` → all clients share one id, so per-user routing is not
  meaningful.
- `auth.type: userpass` → the id is the username.
- `auth.type: command` / `http` → the id is whatever your auth backend returns
  (e.g. the username printed by the auth script).

## Static config (warm start)

```yaml
# Default outbound for everyone without a per-user entry.
outbounds:
  - name: default
    type: direct

# Per-user outbounds. Optional; entries can also be pushed at runtime.
userOutbounds:
  - user: alice
    socks5:
      addr: 1.1.1.1:1080
      username: u        # optional
      password: p        # optional
  - user: bob
    socks5:
      addr: 2.2.2.2:1080

# Required for the runtime /outbound API below.
trafficStats:
  listen: 127.0.0.1:9999
  secret: your-secret
```

With this config `alice` and `bob` egress through their own SOCKS5 proxies,
everyone else goes direct.

## Runtime API

When `trafficStats.listen` is set, the server also serves `/outbound` on the
same address, authenticated with the same `Authorization: <secret>` header.

| Method | Path        | Body                                   | Effect |
|--------|-------------|----------------------------------------|--------|
| GET    | `/outbound` | —                                      | Current map (passwords omitted). |
| POST   | `/outbound` | `{ "<user>": <outbound>, ... }`        | Upsert. `type: direct`/empty removes a user. |
| DELETE | `/outbound` | `[ "<user>", ... ]`                    | Revert these users to the default outbound. |

`<outbound>` is `{ "type": "socks5", "addr": "host:port", "username": "...", "password": "..." }`.

### Examples

```sh
H='-H Authorization:your-secret'

# Route alice through a SOCKS5 proxy, and reset bob to default — in one call.
curl $H -XPOST http://127.0.0.1:9999/outbound -d \
  '{"alice":{"type":"socks5","addr":"1.1.1.1:1080","username":"u","password":"p"},"bob":{"type":"direct"}}'

# Inspect the current mapping (no passwords).
curl $H http://127.0.0.1:9999/outbound

# Remove alice's per-user outbound.
curl $H -XDELETE http://127.0.0.1:9999/outbound -d '["alice"]'
```

Changes apply to new TCP requests immediately and to live UDP sessions on their
next packet; existing connections already dialed are not torn down.

## Notes / limitations

- Only SOCKS5 per-user outbounds are supported for now (the default/global
  `outbounds` still supports direct/http/socks5 as upstream).
- A per-user outbound sends **all** of that user's traffic through the proxy; it
  bypasses the global ACL for that user. Per-user ACL is not implemented.
- The map is in-memory: it is lost on restart. Re-push it from your control
  plane (or rely on `userOutbounds` for warm start).
- Keep `trafficStats.listen` on loopback; the `/outbound` API can set upstream
  proxy credentials.
