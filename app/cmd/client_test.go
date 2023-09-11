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
			SNI:       "another.example.com",
			Insecure:  true,
			PinSHA256: "114515DEADBEEF",
			CA:        "custom_ca.crt",
		},
		QUIC: clientConfigQUIC{
			InitStreamReceiveWindow:     1145141,
			MaxStreamReceiveWindow:      1145142,
			InitConnectionReceiveWindow: 1145143,
			MaxConnectionReceiveWindow:  1145144,
			MaxIdleTimeout:              10 * time.Second,
			KeepAlivePeriod:             4 * time.Second,
			DisablePathMTUDiscovery:     true,
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
