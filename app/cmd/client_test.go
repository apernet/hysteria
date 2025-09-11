package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/spf13/viper"
)

// TestClientConfig tests the parsing of the client config
func TestClientConfig(t *testing.T) {
	viper.SetConfigFile("client_test.yaml")
	err := viper.ReadInConfig()
	assert.NoError(t, err)
	var config clientConfig
	err = viper.Unmarshal(&config)
	assert.NoError(t, err)
	assert.Equal(t, config, clientConfig{
		Server: "example.com",
		Auth:   "weak_ahh_password",
		Transport: clientConfigTransport{
			Type: "udp",
			UDP: clientConfigTransportUDP{
				HopInterval: 30 * time.Second,
			},
		},
		Obfs: clientConfigObfs{
			Type: "salamander",
			Salamander: clientConfigObfsSalamander{
				Password: "cry_me_a_r1ver",
			},
		},
		TLS: clientConfigTLS{
			SNI:               "another.example.com",
			Insecure:          true,
			PinSHA256:         "114515DEADBEEF",
			CA:                "custom_ca.crt",
			ClientCertificate: "client.crt",
			ClientKey:         "client.key",
		},
		QUIC: clientConfigQUIC{
			InitStreamReceiveWindow:     1145141,
			MaxStreamReceiveWindow:      1145142,
			InitConnectionReceiveWindow: 1145143,
			MaxConnectionReceiveWindow:  1145144,
			MaxIdleTimeout:              10 * time.Second,
			KeepAlivePeriod:             4 * time.Second,
			DisablePathMTUDiscovery:     true,
			Sockopts: clientConfigQUICSockopts{
				BindInterface:       stringRef("eth0"),
				FirewallMark:        uint32Ref(1234),
				FdControlUnixSocket: stringRef("test.sock"),
			},
		},
		Bandwidth: clientConfigBandwidth{
			Up:   "200 mbps",
			Down: "1 gbps",
		},
		FastOpen: true,
		Lazy:     true,
		SOCKS5: &socks5Config{
			Listen:     "127.0.0.1:1080",
			Username:   "anon",
			Password:   "bro",
			DisableUDP: true,
		},
		HTTP: &httpConfig{
			Listen:   "127.0.0.1:8080",
			Username: "qqq",
			Password: "bruh",
			Realm:    "martian",
		},
		TCPForwarding: []tcpForwardingEntry{
			{
				Listen: "127.0.0.1:8088",
				Remote: "internal.example.com:80",
			},
		},
		UDPForwarding: []udpForwardingEntry{
			{
				Listen:  "127.0.0.1:5353",
				Remote:  "internal.example.com:53",
				Timeout: 50 * time.Second,
			},
		},
		TCPTProxy: &tcpTProxyConfig{
			Listen: "127.0.0.1:2500",
		},
		UDPTProxy: &udpTProxyConfig{
			Listen:  "127.0.0.1:2501",
			Timeout: 20 * time.Second,
		},
		TCPRedirect: &tcpRedirectConfig{
			Listen: "127.0.0.1:3500",
		},
		TUN: &tunConfig{
			Name:    "hytun",
			MTU:     1500,
			Timeout: 60 * time.Second,
			Address: struct {
				IPv4 string `mapstructure:"ipv4"`
				IPv6 string `mapstructure:"ipv6"`
			}{IPv4: "100.100.100.101/30", IPv6: "2001::ffff:ffff:ffff:fff1/126"},
			Route: &struct {
				Strict      bool     `mapstructure:"strict"`
				IPv4        []string `mapstructure:"ipv4"`
				IPv6        []string `mapstructure:"ipv6"`
				IPv4Exclude []string `mapstructure:"ipv4Exclude"`
				IPv6Exclude []string `mapstructure:"ipv6Exclude"`
			}{
				Strict:      true,
				IPv4:        []string{"0.0.0.0/0"},
				IPv6:        []string{"2000::/3"},
				IPv4Exclude: []string{"192.0.2.1/32"},
				IPv6Exclude: []string{"2001:db8::1/128"},
			},
		},
	})
}

// TestClientConfigURI tests URI-related functions of clientConfig
func TestClientConfigURI(t *testing.T) {
	tests := []struct {
		uri    string
		uriOK  bool
		config *clientConfig
	}{
		{
			uri:   "hysteria2://god@zilla.jp/",
			uriOK: true,
			config: &clientConfig{
				Server: "zilla.jp",
				Auth:   "god",
			},
		},
		{
			uri:   "hysteria2://john:wick@continental.org:4443/",
			uriOK: true,
			config: &clientConfig{
				Server: "continental.org:4443",
				Auth:   "john:wick",
			},
		},
		{
			uri:   "hysteria2://saul@better.call:7000-10000,20000/",
			uriOK: true,
			config: &clientConfig{
				Server: "better.call:7000-10000,20000",
				Auth:   "saul",
			},
		},
		{
			uri:   "hysteria2://noauth.com/?insecure=1&obfs=salamander&obfs-password=66ccff&pinSHA256=deadbeef&sni=crap.cc",
			uriOK: true,
			config: &clientConfig{
				Server: "noauth.com",
				Auth:   "",
				Obfs: clientConfigObfs{
					Type: "salamander",
					Salamander: clientConfigObfsSalamander{
						Password: "66ccff",
					},
				},
				TLS: clientConfigTLS{
					SNI:       "crap.cc",
					Insecure:  true,
					PinSHA256: "deadbeef",
				},
			},
		},
		{
			uri:    "invalid.bs",
			uriOK:  false,
			config: nil,
		},
		{
			uri:    "https://www.google.com/search?q=test",
			uriOK:  false,
			config: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.uri, func(t *testing.T) {
			// Test parseURI
			nc := &clientConfig{Server: test.uri}
			assert.Equal(t, nc.parseURI(), test.uriOK)
			if test.uriOK {
				assert.Equal(t, nc, test.config)
			}
			// Test URI generation
			if test.config != nil {
				assert.Equal(t, test.config.URI(), test.uri)
			}
		})
	}
}

func stringRef(s string) *string {
	return &s
}

func uint32Ref(i uint32) *uint32 {
	return &i
}
