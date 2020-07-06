module github.com/tobyxdd/hysteria

go 1.14

require (
	github.com/elazarl/goproxy v0.0.0-20200426045556-49ad98f6dac1
	github.com/golang/protobuf v1.4.0
	github.com/hashicorp/golang-lru v0.5.4
	github.com/lucas-clemente/quic-go v0.16.1
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/sirupsen/logrus v1.6.0
	github.com/txthinking/runnergroup v0.0.0-20200327135940-540a793bb997 // indirect
	github.com/txthinking/socks5 v0.0.0-20200327133705-caf148ab5e9d
	github.com/txthinking/x v0.0.0-20200330144832-5ad2416896a9 // indirect
)

replace github.com/lucas-clemente/quic-go => github.com/tobyxdd/quic-go v0.2.0-tquic-2
