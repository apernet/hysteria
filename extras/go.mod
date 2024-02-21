module github.com/apernet/hysteria/extras

go 1.21

require (
	github.com/apernet/hysteria/core v0.0.0-00010101000000-000000000000
	github.com/babolivier/go-doh-client v0.0.0-20201028162107-a76cff4cb8b6
	github.com/hashicorp/golang-lru/v2 v2.0.5
	github.com/miekg/dns v1.1.55
	github.com/stretchr/testify v1.8.4
	github.com/txthinking/socks5 v0.0.0-20230325130024-4230056ae301
	golang.org/x/crypto v0.17.0
	golang.org/x/net v0.17.0
	google.golang.org/protobuf v1.28.1
)

require (
	github.com/apernet/quic-go v0.41.1-0.20240122005439-5bf4609c416f // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/google/pprof v0.0.0-20210407192527-94a9f03dee38 // indirect
	github.com/onsi/ginkgo/v2 v2.9.5 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
	github.com/txthinking/runnergroup v0.0.0-20210608031112-152c7c4432bf // indirect
	go.uber.org/mock v0.3.0 // indirect
	golang.org/x/exp v0.0.0-20221205204356-47842c84f3db // indirect
	golang.org/x/mod v0.12.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/tools v0.11.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/apernet/hysteria/core => ../core
