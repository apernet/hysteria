package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"time"
)

const (
	mbpsToBps   = 125000
	dialTimeout = 10 * time.Second

	DefaultMaxReceiveStreamFlowControlWindow     = 33554432
	DefaultMaxReceiveConnectionFlowControlWindow = 67108864
	DefaultMaxIncomingStreams                    = 200
)

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
