package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/spf13/viper"
)

// TestServerConfig tests the parsing of the server config
func TestServerConfig(t *testing.T) {
	viper.SetConfigFile("server_test.yaml")
	err := viper.ReadInConfig()
	assert.NoError(t, err)
	var config serverConfig
	err = viper.Unmarshal(&config)
	assert.NoError(t, err)
	assert.Equal(t, config, serverConfig{
		Listen: ":8443",
		Obfs: serverConfigObfs{
			Type: "salamander",
			Salamander: serverConfigObfsSalamander{
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
		QUIC: serverConfigQUIC{
			InitStreamReceiveWindow:     77881,
			MaxStreamReceiveWindow:      77882,
			InitConnectionReceiveWindow: 77883,
			MaxConnectionReceiveWindow:  77884,
			MaxIdleTimeout:              999 * time.Second,
			MaxIncomingStreams:          256,
			DisablePathMTUDiscovery:     true,
		},
		Bandwidth: serverConfigBandwidth{
			Up:   "500 mbps",
			Down: "100 mbps",
		},
		DisableUDP: true,
		Auth: serverConfigAuth{
			Type:     "password",
			Password: "goofy_ahh_password",
		},
		Masquerade: serverConfigMasquerade{
			Type: "proxy",
			File: serverConfigMasqueradeFile{
				Dir: "/www/masq",
			},
			Proxy: serverConfigMasqueradeProxy{
				URL:         "https://some.site.net",
				RewriteHost: true,
			},
		},
	})
}
