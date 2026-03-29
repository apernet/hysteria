package cmd

import (
	"fmt"
	"strings"
)

const (
	congestionTypeBBR  = "bbr"
	congestionTypeReno = "reno"
)

func normalizeCongestionType(congestionType string) (string, error) {
	switch normalized := strings.ToLower(congestionType); normalized {
	case "", congestionTypeBBR:
		return congestionTypeBBR, nil
	case congestionTypeReno:
		return congestionTypeReno, nil
	default:
		return "", fmt.Errorf("unsupported congestion type %q", congestionType)
	}
}

func normalizeBBRProfile(profile string) (string, error) {
	switch normalized := strings.ToLower(profile); normalized {
	case "", "standard":
		return "standard", nil
	case "conservative", "aggressive":
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported BBR profile %q", profile)
	}
}
