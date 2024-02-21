module github.com/apernet/hysteria/app

go 1.21

require (
	github.com/apernet/go-tproxy v0.0.0-20230809025308-8f4723fd742f
	github.com/apernet/hysteria/core v0.0.0-00010101000000-000000000000
	github.com/apernet/hysteria/extras v0.0.0-00010101000000-000000000000
	github.com/caddyserver/certmagic v0.17.2
	github.com/mdp/qrterminal/v3 v3.1.1
	github.com/mholt/acmez v1.0.4
	github.com/spf13/cobra v1.7.0
	github.com/spf13/viper v1.15.0
	github.com/stretchr/testify v1.8.4
	github.com/txthinking/socks5 v0.0.0-20230325130024-4230056ae301
	go.uber.org/zap v1.24.0
)

require (
	github.com/apernet/quic-go v0.41.1-0.20240122005439-5bf4609c416f // indirect
	github.com/babolivier/go-doh-client v0.0.0-20201028162107-a76cff4cb8b6 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/google/pprof v0.0.0-20210407192527-94a9f03dee38 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.5 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/cpuid/v2 v2.1.1 // indirect
	github.com/libdns/libdns v0.2.1 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/miekg/dns v1.1.55 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/onsi/ginkgo/v2 v2.9.5 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pelletier/go-toml/v2 v2.0.6 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/spf13/afero v1.9.3 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
	github.com/subosito/gotenv v1.4.2 // indirect
	github.com/txthinking/runnergroup v0.0.0-20210608031112-152c7c4432bf // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/mock v0.3.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.17.0 // indirect
	golang.org/x/exp v0.0.0-20221205204356-47842c84f3db // indirect
	golang.org/x/mod v0.12.0 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/tools v0.11.1 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/qr v0.2.0 // indirect
)

replace github.com/apernet/hysteria/core => ../core

replace github.com/apernet/hysteria/extras => ../extras
