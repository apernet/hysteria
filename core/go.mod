module github.com/apernet/hysteria/core

go 1.20

require (
	github.com/coreos/go-iptables v0.6.0
	github.com/google/gopacket v1.1.19
	github.com/hashicorp/golang-lru/v2 v2.0.1
	github.com/lunixbochs/struc v0.0.0-20200707160740-784aaebc1d40
	github.com/oschwald/geoip2-golang v1.8.0
	github.com/quic-go/quic-go v0.34.0
	github.com/txthinking/socks5 v0.0.0-20220212043548-414499347d4a
	golang.org/x/sys v0.7.0
)

require (
	github.com/go-task/slim-sprig v0.0.0-20210107165309-348f09dbbbc0 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/google/pprof v0.0.0-20230131232505-5a9e8f65f08f // indirect
	github.com/onsi/ginkgo/v2 v2.8.0 // indirect
	github.com/oschwald/maxminddb-golang v1.10.0 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/quic-go/qtls-go1-19 v0.3.2 // indirect
	github.com/quic-go/qtls-go1-20 v0.2.2 // indirect
	github.com/stretchr/testify v1.8.1 // indirect
	github.com/txthinking/runnergroup v0.0.0-20210608031112-152c7c4432bf // indirect
	github.com/txthinking/x v0.0.0-20210326105829-476fab902fbe // indirect
	golang.org/x/crypto v0.7.0 // indirect
	golang.org/x/exp v0.0.0-20230131160201-f062dba9d201 // indirect
	golang.org/x/mod v0.8.0 // indirect
	golang.org/x/net v0.8.0 // indirect
	golang.org/x/tools v0.6.0 // indirect
	google.golang.org/protobuf v1.28.2-0.20230118093459-a9481185b34d // indirect
)

replace github.com/quic-go/quic-go => github.com/apernet/quic-go v0.34.1-0.20230507231629-ec008b7e8473
