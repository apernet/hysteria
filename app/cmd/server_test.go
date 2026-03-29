package cmd

import (
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	eUtils "github.com/apernet/hysteria/extras/v2/utils"
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
			Cert:     "some.crt",
			Key:      "some.key",
			SNIGuard: "strict",
			ClientCA: "some_ca.crt",
		},
		ACME: &serverConfigACME{
			Domains: []string{
				"sub1.example.com",
				"sub2.example.com",
			},
			Email:      "haha@cringe.net",
			CA:         "zero",
			ListenHost: "127.0.0.9",
			Dir:        "random_dir",
			Type:       "dns",
			HTTP: serverConfigACMEHTTP{
				AltPort: 8888,
			},
			TLS: serverConfigACMETLS{
				AltPort: 44333,
			},
			DNS: serverConfigACMEDNS{
				Name: "gomommy",
				Config: map[string]string{
					"key1": "value1",
					"key2": "value2",
				},
			},
			DisableHTTP:    true,
			DisableTLSALPN: true,
			AltHTTPPort:    8080,
			AltTLSALPNPort: 4433,
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
		Congestion: serverConfigCongestion{
			Type:       "reno",
			BBRProfile: "aggressive",
		},
		Bandwidth: serverConfigBandwidth{
			Up:   "500 mbps",
			Down: "100 mbps",
		},
		IgnoreClientBandwidth: true,
		SpeedTest:             true,
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
		Sniff: serverConfigSniff{
			Enable:        true,
			Timeout:       1 * time.Second,
			RewriteDomain: true,
			TCPPorts:      "80,443,1000-2000",
			UDPPorts:      "443",
		},
		ACL: serverConfigACL{
			File: "chnroute.txt",
			Inline: []string{
				"lmao(ok)",
				"kek(cringe,boba,tea)",
			},
			GeoIP:             "some.dat",
			GeoSite:           "some_site.dat",
			GeoUpdateInterval: 168 * time.Hour,
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
					FastOpen:   true,
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
				XForwarded:  true,
				Insecure:    true,
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

func TestServerFillCongestionConfig(t *testing.T) {
	t.Run("defaults to bbr standard", func(t *testing.T) {
		hyConfig := &server.Config{}
		err := (&serverConfig{}).fillCongestionConfig(hyConfig)
		assert.NoError(t, err)
		assert.Equal(t, "bbr", hyConfig.CongestionConfig.Type)
		assert.Equal(t, "standard", hyConfig.CongestionConfig.BBRProfile)
	})

	t.Run("reno ignores bbr profile", func(t *testing.T) {
		hyConfig := &server.Config{}
		err := (&serverConfig{
			Congestion: serverConfigCongestion{
				Type:       "reno",
				BBRProfile: "invalid",
			},
		}).fillCongestionConfig(hyConfig)
		assert.NoError(t, err)
		assert.Equal(t, "reno", hyConfig.CongestionConfig.Type)
		assert.Empty(t, hyConfig.CongestionConfig.BBRProfile)
	})

	t.Run("rejects invalid type", func(t *testing.T) {
		err := (&serverConfig{
			Congestion: serverConfigCongestion{Type: "cubic"},
		}).fillCongestionConfig(&server.Config{})
		assert.EqualError(t, err, `invalid config: congestion.type: unsupported congestion type "cubic"`)
	})

	t.Run("rejects invalid bbr profile", func(t *testing.T) {
		err := (&serverConfig{
			Congestion: serverConfigCongestion{
				Type:       "bbr",
				BBRProfile: "turbo",
			},
		}).fillCongestionConfig(&server.Config{})
		assert.EqualError(t, err, `invalid config: congestion.bbrProfile: unsupported BBR profile "turbo"`)
	})
}

func TestResolveServerListenAddr(t *testing.T) {
	t.Run("single port", func(t *testing.T) {
		addr, ports, err := resolveServerListenAddr(":8443")
		assert.NoError(t, err)
		assert.Empty(t, ports)
		assert.Equal(t, 8443, addr.Port)
	})

	t.Run("port range", func(t *testing.T) {
		addr, ports, err := resolveServerListenAddr("127.0.0.1:9003-9001,9008")
		assert.NoError(t, err)
		assert.Equal(t, 9001, addr.Port)
		assert.Equal(t, eUtils.PortUnion{{Start: 9001, End: 9003}, {Start: 9008, End: 9008}}, ports)
	})

	t.Run("invalid range", func(t *testing.T) {
		_, _, err := resolveServerListenAddr("127.0.0.1:9001-")
		assert.EqualError(t, err, "9001- is not a valid port number or range")
	})
}
