package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println()
		fmt.Printf("Usage: %s MODE [OPTIONS]\n\n"+
			"Modes: server / client\n"+
			"Use -h to see the available options for a mode.\n\n", os.Args[0])
		return
	}
	mode := strings.ToLower(strings.TrimSpace(os.Args[1]))
	switch mode {
	case "server", "s":
		server(os.Args[2:])
	case "client", "c":
		client(os.Args[2:])
	default:
		fmt.Println("Invalid mode:", mode)
	}
}
