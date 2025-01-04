//go:build windows

package tun

import (
	"golang.org/x/sys/windows"
)

func isIPv6Supported() bool {
	var wsaData windows.WSAData
	err := windows.WSAStartup(uint32(0x202), &wsaData)
	if err != nil {
		// Failing silently: it is not our duty to report such errors
		return true
	}
	defer windows.WSACleanup()

	sock, err := windows.Socket(windows.AF_INET6, windows.SOCK_DGRAM, windows.IPPROTO_UDP)
	if err != nil {
		return false
	}
	_ = windows.Closesocket(sock)
	return true
}
