package main

import (
	"fmt"
	"io"

	"github.com/apernet/hysteria/sdk"
)

func main() {
	config := sdk.ClientConfig{
		ServerAddress: "just.example.net:6677",
		Protocol:      sdk.ProtocolUDP,
		Obfs:          "password1234",
		SendBPS:       524288,
		RecvBPS:       524288,
	}
	client, err := sdk.NewClient(config)
	if err != nil {
		fmt.Println("NewClient:", err)
		return
	}
	defer client.Close()

	conn, err := client.DialTCP("ipinfo.io:80")
	if err != nil {
		fmt.Println("DialTCP:", err)
		return
	}
	defer conn.Close()

	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: ipinfo.io\r\nConnection: close\r\n\r\n"))
	if err != nil {
		fmt.Println("Write:", err)
		return
	}
	bs, err := io.ReadAll(conn)
	if err != nil {
		fmt.Println("ReadAll:", err)
		return
	}
	fmt.Println(string(bs))
}
