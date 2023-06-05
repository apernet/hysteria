//go:build windows
// +build windows

package main

import (
	"golang.org/x/sys/windows"
	"os"
)

// Add console VT color mode
func openWinVT() {
	stdout := windows.Handle(os.Stdout.Fd())

	var mode uint32
	windows.GetConsoleMode(stdout, &mode)

	mode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING // Add VT Color Support

	windows.SetConsoleMode(stdout, mode)
}
