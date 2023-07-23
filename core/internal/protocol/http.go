package protocol

import (
	"net/http"
	"strconv"
)

const (
	URLHost = "hysteria"
	URLPath = "/auth"

	RequestHeaderAuth        = "Hysteria-Auth"
	ResponseHeaderUDPEnabled = "Hysteria-UDP"
	CommonHeaderCCRX         = "Hysteria-CC-RX"
	CommonHeaderPadding      = "Hysteria-Padding"

	StatusAuthOK = 233
)

func AuthRequestDataFromHeader(h http.Header) (auth string, rx uint64) {
	auth = h.Get(RequestHeaderAuth)
	rx, _ = strconv.ParseUint(h.Get(CommonHeaderCCRX), 10, 64)
	return
}

func AuthRequestDataToHeader(h http.Header, auth string, rx uint64) {
	h.Set(RequestHeaderAuth, auth)
	h.Set(CommonHeaderCCRX, strconv.FormatUint(rx, 10))
	h.Set(CommonHeaderPadding, authRequestPadding.String())
}

func AuthResponseDataFromHeader(h http.Header) (udp bool, rx uint64) {
	udp, _ = strconv.ParseBool(h.Get(ResponseHeaderUDPEnabled))
	rx, _ = strconv.ParseUint(h.Get(CommonHeaderCCRX), 10, 64)
	return
}

func AuthResponseDataToHeader(h http.Header, udp bool, rx uint64) {
	h.Set(ResponseHeaderUDPEnabled, strconv.FormatBool(udp))
	h.Set(CommonHeaderCCRX, strconv.FormatUint(rx, 10))
	h.Set(CommonHeaderPadding, authResponsePadding.String())
}
