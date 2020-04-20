package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
)

const (
	mbpsToBps = 125000

	TLSAppProtocol = "hysteria-relay"

	DefaultMaxReceiveStreamFlowControlWindow     = 33554432
	DefaultMaxReceiveConnectionFlowControlWindow = 67108864
)

type cmdClientConfig struct {
	ListenAddr        string `json:"listen" desc:"TCP listen address"`
	ServerAddr        string `json:"server" desc:"Server address"`
	Name              string `json:"name" desc:"Client name presented to the server"`
	Insecure          bool   `json:"insecure" desc:"Ignore TLS certificate errors"`
	CustomCAFile      string `json:"ca" desc:"Specify a trusted CA file"`
	UpMbps            int    `json:"up_mbps" desc:"Upload speed in Mbps"`
	DownMbps          int    `json:"down_mbps" desc:"Download speed in Mbps"`
	ReceiveWindowConn uint64 `json:"recv_window_conn" desc:"Max receive window size per connection"`
	ReceiveWindow     uint64 `json:"recv_window" desc:"Max receive window size"`
}

func (c *cmdClientConfig) Check() error {
	if len(c.ListenAddr) == 0 {
		return errors.New("no listen address")
	}
	if len(c.ServerAddr) == 0 {
		return errors.New("no server address")
	}
	if c.UpMbps <= 0 || c.DownMbps <= 0 {
		return errors.New("invalid speed")
	}
	if (c.ReceiveWindowConn != 0 && c.ReceiveWindowConn < 65536) ||
		(c.ReceiveWindow != 0 && c.ReceiveWindow < 65536) {
		return errors.New("invalid receive window size")
	}
	return nil
}

type cmdServerConfig struct {
	ListenAddr          string `json:"listen" desc:"Server listen address"`
	RemoteAddr          string `json:"remote" desc:"Remote relay address"`
	CertFile            string `json:"cert" desc:"TLS certificate file"`
	KeyFile             string `json:"key" desc:"TLS key file"`
	UpMbps              int    `json:"up_mbps" desc:"Max upload speed per client in Mbps"`
	DownMbps            int    `json:"down_mbps" desc:"Max download speed per client in Mbps"`
	ReceiveWindowConn   uint64 `json:"recv_window_conn" desc:"Max receive window size per connection"`
	ReceiveWindowClient uint64 `json:"recv_window_client" desc:"Max receive window size per client"`
	MaxConnClient       int    `json:"max_conn_client" desc:"Max simultaneous connections allowed per client"`
}

func (c *cmdServerConfig) Check() error {
	if len(c.ListenAddr) == 0 {
		return errors.New("no listen address")
	}
	if len(c.RemoteAddr) == 0 {
		return errors.New("no remote address")
	}
	if len(c.CertFile) == 0 || len(c.KeyFile) == 0 {
		return errors.New("TLS cert or key not provided")
	}
	if c.UpMbps < 0 || c.DownMbps < 0 {
		return errors.New("invalid speed")
	}
	if (c.ReceiveWindowConn != 0 && c.ReceiveWindowConn < 65536) ||
		(c.ReceiveWindowClient != 0 && c.ReceiveWindowClient < 65536) {
		return errors.New("invalid receive window size")
	}
	if c.MaxConnClient < 0 {
		return errors.New("invalid max connections per client")
	}
	return nil
}

func loadConfig(cfg interface{}, args []string) error {
	cfgVal := reflect.ValueOf(cfg).Elem()
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	fsValMap := make(map[reflect.Value]interface{}, cfgVal.NumField())
	for i := 0; i < cfgVal.NumField(); i++ {
		structField := cfgVal.Type().Field(i)
		tag := structField.Tag
		switch structField.Type.Kind() {
		case reflect.String:
			fsValMap[cfgVal.Field(i)] =
				fs.String(jsonTagToFlagName(tag.Get("json")), "", tag.Get("desc"))
		case reflect.Int:
			fsValMap[cfgVal.Field(i)] =
				fs.Int(jsonTagToFlagName(tag.Get("json")), 0, tag.Get("desc"))
		case reflect.Uint64:
			fsValMap[cfgVal.Field(i)] =
				fs.Uint64(jsonTagToFlagName(tag.Get("json")), 0, tag.Get("desc"))
		case reflect.Bool:
			var bf optionalBoolFlag
			fs.Var(&bf, jsonTagToFlagName(tag.Get("json")), tag.Get("desc"))
			fsValMap[cfgVal.Field(i)] = &bf
		}
	}
	configFile := fs.String("config", "", "Configuration file")
	// Parse
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	// Put together the config
	if len(*configFile) > 0 {
		cb, err := ioutil.ReadFile(*configFile)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(cb, cfg); err != nil {
			return err
		}
	}
	// Flags override config from file
	for field, val := range fsValMap {
		switch v := val.(type) {
		case *string:
			if len(*v) > 0 {
				field.SetString(*v)
			}
		case *int:
			if *v != 0 {
				field.SetInt(int64(*v))
			}
		case *uint64:
			if *v != 0 {
				field.SetUint(*v)
			}
		case *optionalBoolFlag:
			if v.Exists {
				field.SetBool(v.Value)
			}
		}
	}
	return nil
}

func jsonTagToFlagName(tag string) string {
	return strings.ReplaceAll(tag, "_", "-")
}
