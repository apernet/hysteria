module github.com/apernet/hysteria/extras/v2

go 1.24

toolchain go1.25.1

require (
	github.com/apernet/hysteria/core/v2 v2.0.0-00010101000000-000000000000
	github.com/apernet/quic-go v0.57.2-0.20260111184307-eec823306178
	github.com/database64128/tfo-go/v2 v2.2.2
	github.com/hashicorp/golang-lru/v2 v2.0.5
	github.com/miekg/dns v1.1.59
	github.com/refraction-networking/utls v1.6.6
	github.com/stretchr/testify v1.11.1
	github.com/txthinking/socks5 v0.0.0-20230325130024-4230056ae301
	golang.org/x/crypto v0.41.0
	golang.org/x/net v0.43.0
	google.golang.org/protobuf v1.34.1
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/cloudflare/circl v1.3.9 // indirect
	github.com/database64128/netx-go v0.0.0-20240905055117-62795b8b054a // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/txthinking/runnergroup v0.0.0-20210608031112-152c7c4432bf // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/mod v0.27.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	golang.org/x/tools v0.36.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/apernet/hysteria/core/v2 => ../core
