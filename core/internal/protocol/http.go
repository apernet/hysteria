package protocol

import (
	"net/http"
	"strconv"
)

const (
	URLHost = "hysteria"
	URLPath = "/auth"

	HeaderAuth = "Hysteria-Auth"
	HeaderCCRX = "Hysteria-CC-RX"

	StatusAuthOK = 233
)

func AuthRequestDataFromHeader(h http.Header) (auth string, rx uint64) {
	auth = h.Get(HeaderAuth)
	rx, _ = strconv.ParseUint(h.Get(HeaderCCRX), 10, 64)
	return
}

func AuthRequestDataToHeader(h http.Header, auth string, rx uint64) {
	h.Set(HeaderAuth, auth)
	h.Set(HeaderCCRX, strconv.FormatUint(rx, 10))
}

func AuthResponseDataFromHeader(h http.Header) (rx uint64) {
	rx, _ = strconv.ParseUint(h.Get(HeaderCCRX), 10, 64)
	return
}

func AuthResponseDataToHeader(h http.Header, rx uint64) {
	h.Set(HeaderCCRX, strconv.FormatUint(rx, 10))
}
