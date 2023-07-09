package cmd

import (
	"reflect"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// TestServerConfig tests the parsing of the server config
func TestServerConfig(t *testing.T) {
	viper.SetConfigFile("server_test.yaml")
	err := viper.ReadInConfig()
	if err != nil {
		t.Fatal("failed to read server config", err)
	}
	var config serverConfig
	if err := viper.Unmarshal(&config); err != nil {
		t.Fatal("failed to parse server config", err)
	}
	if !reflect.DeepEqual(config, serverConfig{
		Listen: ":8443",
		Obfs: struct {
			Type       string `mapstructure:"type"`
			Salamander struct {
				Password string `mapstructure:"password"`
			} `mapstructure:"salamander"`
		}{
			Type: "salamander",
			Salamander: struct {
				Password string `mapstructure:"password"`
			}{
				Password: "cry_me_a_r1ver",
			},
		},
		TLS: &serverConfigTLS{
			Cert: "some.crt",
			Key:  "some.key",
		},
		ACME: &serverConfigACME{
			Domains: []string{
				"sub1.example.com",
				"sub2.example.com",
			},
			Email:          "haha@cringe.net",
			CA:             "zero",
			DisableHTTP:    true,
			DisableTLSALPN: true,
			AltHTTPPort:    9980,
			AltTLSALPNPort: 9443,
			Dir:            "random_dir",
		},
		QUIC: struct {
			InitStreamReceiveWindow     uint64        `mapstructure:"initStreamReceiveWindow"`
			MaxStreamReceiveWindow      uint64        `mapstructure:"maxStreamReceiveWindow"`
			InitConnectionReceiveWindow uint64        `mapstructure:"initConnReceiveWindow"`
			MaxConnectionReceiveWindow  uint64        `mapstructure:"maxConnReceiveWindow"`
			MaxIdleTimeout              time.Duration `mapstructure:"maxIdleTimeout"`
			MaxIncomingStreams          int64         `mapstructure:"maxIncomingStreams"`
			DisablePathMTUDiscovery     bool          `mapstructure:"disablePathMTUDiscovery"`
		}{
			InitStreamReceiveWindow:     77881,
			MaxStreamReceiveWindow:      77882,
			InitConnectionReceiveWindow: 77883,
			MaxConnectionReceiveWindow:  77884,
			MaxIdleTimeout:              999 * time.Second,
			MaxIncomingStreams:          256,
			DisablePathMTUDiscovery:     true,
		},
		Bandwidth: struct {
			Up   string `mapstructure:"up"`
			Down string `mapstructure:"down"`
		}{
			Up:   "500 mbps",
			Down: "100 mbps",
		},
		DisableUDP: true,
		Auth: struct {
			Type     string `mapstructure:"type"`
			Password string `mapstructure:"password"`
		}{
			Type:     "password",
			Password: "goofy_ahh_password",
		},
		Masquerade: struct {
			Type string `mapstructure:"type"`
			File struct {
				Dir string `mapstructure:"dir"`
			} `mapstructure:"file"`
			Proxy struct {
				URL         string `mapstructure:"url"`
				RewriteHost bool   `mapstructure:"rewriteHost"`
			} `mapstructure:"proxy"`
		}{
			Type: "proxy",
			File: struct {
				Dir string `mapstructure:"dir"`
			}{
				Dir: "/www/masq",
			},
			Proxy: struct {
				URL         string `mapstructure:"url"`
				RewriteHost bool   `mapstructure:"rewriteHost"`
			}{
				URL:         "https://some.site.net",
				RewriteHost: true,
			},
		},
	}) {
		t.Fatal("parsed server config is not equal to expected")
	}
}
