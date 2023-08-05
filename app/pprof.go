//go:build pprof

package main

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"
)

const (
	pprofListenAddr = ":6060"
)

func init() {
	fmt.Printf("!!! pprof enabled, listening on %s\n", pprofListenAddr)
	go func() {
		if err := http.ListenAndServe(pprofListenAddr, nil); err != nil {
			panic(err)
		}
	}()
}
