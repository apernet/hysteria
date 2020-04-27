module github.com/tobyxdd/hysteria

go 1.14

require github.com/golang/protobuf v1.3.1

require (
	github.com/hashicorp/golang-lru v0.5.4
	github.com/lucas-clemente/quic-go v0.15.2
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/txthinking/runnergroup v0.0.0-20200327135940-540a793bb997 // indirect
	github.com/txthinking/socks5 v0.0.0-20200327133705-caf148ab5e9d
	github.com/txthinking/x v0.0.0-20200330144832-5ad2416896a9 // indirect
)

replace github.com/lucas-clemente/quic-go => github.com/tobyxdd/quic-go v0.1.3-tquic-1
