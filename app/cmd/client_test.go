package cmd

import (
	"reflect"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// TestClientConfig tests the parsing of the client config
func TestClientConfig(t *testing.T) {
	viper.SetConfigFile("client_test.yaml")
	err := viper.ReadInConfig()
	if err != nil {
		t.Fatal("failed to read client config", err)
	}
	var config clientConfig
	if err := viper.Unmarshal(&config); err != nil {
		t.Fatal("failed to parse client config", err)
	}
	if !reflect.DeepEqual(config, clientConfig{
		Server: "example.com",
		Auth:   "weak_ahh_password",
		TLS: struct {
			SNI      string `mapstructure:"sni"`
			Insecure bool   `mapstructure:"insecure"`
			CA       string `mapstructure:"ca"`
		}{
			SNI:      "another.example.com",
			Insecure: true,
			CA:       "custom_ca.crt",
		},
		QUIC: struct {
			InitStreamReceiveWindow     uint64        `mapstructure:"initStreamReceiveWindow"`
			MaxStreamReceiveWindow      uint64        `mapstructure:"maxStreamReceiveWindow"`
			InitConnectionReceiveWindow uint64        `mapstructure:"initConnReceiveWindow"`
			MaxConnectionReceiveWindow  uint64        `mapstructure:"maxConnReceiveWindow"`
			MaxIdleTimeout              time.Duration `mapstructure:"maxIdleTimeout"`
			KeepAlivePeriod             time.Duration `mapstructure:"keepAlivePeriod"`
			DisablePathMTUDiscovery     bool          `mapstructure:"disablePathMTUDiscovery"`
		}{
			InitStreamReceiveWindow:     1145141,
			MaxStreamReceiveWindow:      1145142,
			InitConnectionReceiveWindow: 1145143,
			MaxConnectionReceiveWindow:  1145144,
			MaxIdleTimeout:              10 * time.Second,
			KeepAlivePeriod:             4 * time.Second,
			DisablePathMTUDiscovery:     true,
		},
		Bandwidth: struct {
			Up   string `mapstructure:"up"`
			Down string `mapstructure:"down"`
		}{
			Up:   "200 mbps",
			Down: "1 gbps",
		},
		FastOpen: true,
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
		Forwarding: []forwardingEntry{
			{
				Listen:   "127.0.0.1:8088",
				Remote:   "internal.example.com:80",
				Protocol: "tcp",
			},
			{
				Listen:     "127.0.0.1:5353",
				Remote:     "internal.example.com:53",
				Protocol:   "udp",
				UDPTimeout: 50 * time.Second,
			},
		},
	}) {
		t.Fatal("parsed client config is not equal to expected")
	}
}
