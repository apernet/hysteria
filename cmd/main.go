package main

import (
	"fmt"
	"os"
	"strings"
)

var modeMap = map[string]func(args []string){
	"relay server": relayServer,
	"relay client": relayClient,
	"proxy server": proxyServer,
	"proxy client": proxyClient,
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println()
		fmt.Printf("Usage: %s MODE SUBMODE [OPTIONS]\n\n"+
			"Available mode/submode combinations: "+getModes()+"\n"+
			"Use -h to see the available options for a mode.\n\n", os.Args[0])
		return
	}
	modeStr := fmt.Sprintf("%s %s", strings.ToLower(strings.TrimSpace(os.Args[1])),
		strings.ToLower(strings.TrimSpace(os.Args[2])))
	f := modeMap[modeStr]
	if f != nil {
		f(os.Args[3:])
	} else {
		fmt.Println("Invalid mode:", modeStr)
	}
}

func getModes() string {
	modes := make([]string, 0, len(modeMap))
	for mode := range modeMap {
		modes = append(modes, mode)
	}
	return strings.Join(modes, ", ")
}
