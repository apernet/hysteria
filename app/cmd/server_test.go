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
		IgnoreClientBandwidth: true,
		DisableUDP:            true,
		UDPIdleTimeout:        120 * time.Second,
		Auth: serverConfigAuth{
			Type:     "password",
			Password: "goofy_ahh_password",
			UserPass: map[string]string{
				"yolo": "swag",
				"lol":  "kek",
				"foo":  "bar",
			},
			HTTP: serverConfigAuthHTTP{
				URL:      "http://127.0.0.1:5000/auth",
				Insecure: true,
			},
			Command: "/etc/some_command",
		},
		Resolver: serverConfigResolver{
			Type: "udp",
			TCP: serverConfigResolverTCP{
				Addr:    "123.123.123.123:5353",
				Timeout: 4 * time.Second,
			},
			UDP: serverConfigResolverUDP{
				Addr:    "4.6.8.0:53",
				Timeout: 2 * time.Second,
			},
			TLS: serverConfigResolverTLS{
				Addr:     "dot.yolo.com:8853",
				Timeout:  10 * time.Second,
				SNI:      "server1.yolo.net",
				Insecure: true,
			},
			HTTPS: serverConfigResolverHTTPS{
				Addr:     "cringe.ahh.cc",
				Timeout:  5 * time.Second,
				SNI:      "real.stuff.net",
				Insecure: true,
			},
		},
		ACL: serverConfigACL{
			File: "chnroute.txt",
			Inline: []string{
				"lmao(ok)",
				"kek(cringe,boba,tea)",
			},
			GeoIP:   "some.dat",
			GeoSite: "some_site.dat",
		},
		Outbounds: []serverConfigOutboundEntry{
			{
				Name: "goodstuff",
				Type: "direct",
				Direct: serverConfigOutboundDirect{
					Mode:       "64",
					BindIPv4:   "2.4.6.8",
					BindIPv6:   "0:0:0:0:0:ffff:0204:0608",
					BindDevice: "eth233",
				},
			},
			{
				Name: "badstuff",
				Type: "socks5",
				SOCKS5: serverConfigOutboundSOCKS5{
					Addr:     "shady.proxy.ru:1080",
					Username: "hackerman",
					Password: "Elliot Alderson",
				},
			},
			{
				Name: "weirdstuff",
				Type: "http",
				HTTP: serverConfigOutboundHTTP{
					URL:      "https://eyy.lmao:4443/goofy",
					Insecure: true,
				},
			},
		},
		TrafficStats: serverConfigTrafficStats{
			Listen: ":9999",
			Secret: "its_me_mario",
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
			String: serverConfigMasqueradeString{
				Content: "aint nothin here",
				Headers: map[string]string{
					"content-type": "text/plain",
					"custom-haha":  "lol",
				},
				StatusCode: 418,
			},
			ListenHTTP:  ":80",
			ListenHTTPS: ":443",
			ForceHTTPS:  true,
		},
	})
}
