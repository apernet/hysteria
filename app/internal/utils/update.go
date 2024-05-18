package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
)

const (
	updateCheckEndpoint = "https://api.hy2.io/v1/update"
	updateCheckTimeout  = 10 * time.Second
)

type UpdateChecker struct {
	CurrentVersion string
	Platform       string
	Architecture   string
	Channel        string
	Side           string
	Client         *http.Client
}

func NewServerUpdateChecker(currentVersion, platform, architecture, channel string) *UpdateChecker {
	return &UpdateChecker{
		CurrentVersion: currentVersion,
		Platform:       platform,
		Architecture:   architecture,
		Channel:        channel,
		Side:           "server",
		Client: &http.Client{
			Timeout: updateCheckTimeout,
		},
	}
}

// NewClientUpdateChecker ensures that update checks are routed through a HyClient,
// not being sent directly. This safeguard is CRITICAL, especially in scenarios where
// users use Hysteria to bypass censorship. Making direct HTTPS requests to the API
// endpoint could be easily spotted by censors (through SNI, for example), and could
// serve as a signal to identify and penalize Hysteria users.
func NewClientUpdateChecker(currentVersion, platform, architecture, channel string, hyClient client.Client) *UpdateChecker {
	return &UpdateChecker{
		CurrentVersion: currentVersion,
		Platform:       platform,
		Architecture:   architecture,
		Channel:        channel,
		Side:           "client",
		Client: &http.Client{
			Timeout: updateCheckTimeout,
			Transport: &http.Transport{
				DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
					// Unfortunately HyClient doesn't support context for now
					return hyClient.TCP(addr)
				},
			},
		},
	}
}

type UpdateResponse struct {
	HasUpdate     bool   `json:"update"`
	LatestVersion string `json:"lver"`
	URL           string `json:"url"`
	Urgent        bool   `json:"urgent"`
}

func (uc *UpdateChecker) Check() (*UpdateResponse, error) {
	url := fmt.Sprintf("%s?cver=%s&plat=%s&arch=%s&chan=%s&side=%s",
		updateCheckEndpoint,
		uc.CurrentVersion,
		uc.Platform,
		uc.Architecture,
		uc.Channel,
		uc.Side,
	)
	resp, err := uc.Client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	var uResp UpdateResponse
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&uResp); err != nil {
		return nil, err
	}
	return &uResp, nil
}
