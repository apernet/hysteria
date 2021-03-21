# ACL File Format

ACL files describe how to process incoming requests. Both the server and the client support ACL and follow the identical
syntax.

```
action condition_type condition argument
```

Example:

```
direct domain evil.corp
proxy domain-suffix google.com
block ip 1.2.3.4
hijack cidr 192.168.1.1/24 127.0.0.1

direct all
```

A real-life ACL example of directly connecting to all China IPs (and its generator Python
script) [can be found here](docs/acl).

Hysteria acts according to the first matching rule in the file for each request. When there is no match, the default
behavior is to proxy all connections. You can override this by adding a rule at the end of the file with the condition
`all`.

4 actions:

`direct` - connect directly to the target server without going through the proxy

`proxy` - connect to the target server through the proxy (only available on the client)

`block` - block the connection from establishing

`hijack` - hijack the connection to another target address (must be specified in the argument)

5 condition types:

`domain` - match a specific domain (does NOT match subdomains! e.g. `apple.com` will not match `cdn.apple.com`)

`domain-suffix` - match a domain suffix (match subdomains, but `apple.com` will still not match `fakeapple.com`)

`cidr` - IPv4 or IPv6 CIDR

`ip` - IPv4 or IPv6 address

`all` - match anything (usually placed at the end of the file as a default rule)

For domain requests, Hysteria will try to resolve the domains and match both domain & IP rules. In other words, an IP
rule covers all connections that would end up connecting to this IP, regardless of whether the client requests with IP
or domain.