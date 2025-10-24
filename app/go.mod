module github.com/apernet/hysteria/app/v2

go 1.23

toolchain go1.25.1

require (
	github.com/apernet/go-tproxy v0.0.0-20230809025308-8f4723fd742f
	github.com/apernet/hysteria/core/v2 v2.0.0-00010101000000-000000000000
	github.com/apernet/hysteria/extras/v2 v2.0.0-00010101000000-000000000000
	github.com/apernet/sing-tun v0.2.6-0.20250920121535-299f04629986
	github.com/caddyserver/certmagic v0.17.2
	github.com/libdns/cloudflare v0.1.1
	github.com/libdns/duckdns v0.2.0
	github.com/libdns/gandi v1.0.3
	github.com/libdns/godaddy v1.0.3
	github.com/libdns/namedotcom v0.3.3
	github.com/libdns/vultr v1.0.0
	github.com/mdp/qrterminal/v3 v3.1.1
	github.com/mholt/acmez v1.0.4
	github.com/sagernet/sing v0.3.2
	github.com/spf13/cobra v1.7.0
	github.com/spf13/viper v1.15.0
	github.com/stretchr/testify v1.9.0
	github.com/txthinking/socks5 v0.0.0-20230325130024-4230056ae301
	go.uber.org/zap v1.24.0
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842
	golang.org/x/sys v0.25.0
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/apernet/quic-go v0.54.1-0.20251024023933-5e0818a71079 // indirect
	github.com/cloudflare/circl v1.3.9 // indirect
	github.com/database64128/netx-go v0.0.0-20240905055117-62795b8b054a // indirect
	github.com/database64128/tfo-go/v2 v2.2.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.6 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.5 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/klauspost/cpuid/v2 v2.1.1 // indirect
	github.com/libdns/libdns v0.2.2 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/miekg/dns v1.1.59 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pelletier/go-toml/v2 v2.0.6 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	github.com/refraction-networking/utls v1.6.6 // indirect
	github.com/sagernet/netlink v0.0.0-20220905062125-8043b4a9aa97 // indirect
	github.com/scjalliance/comshim v0.0.0-20230315213746-5e51f40bd3b9 // indirect
	github.com/spf13/afero v1.9.3 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/subosito/gotenv v1.4.2 // indirect
	github.com/txthinking/runnergroup v0.0.0-20210608031112-152c7c4432bf // indirect
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74 // indirect
	github.com/vultr/govultr/v3 v3.6.4 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/mock v0.5.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/crypto v0.26.0 // indirect
	golang.org/x/mod v0.18.0 // indirect
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/oauth2 v0.20.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	golang.org/x/tools v0.22.0 // indirect
	google.golang.org/protobuf v1.34.1 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/qr v0.2.0 // indirect
)

replace github.com/apernet/hysteria/core/v2 => ../core

replace github.com/apernet/hysteria/extras/v2 => ../extras
