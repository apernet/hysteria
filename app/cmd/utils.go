package cmd

import (
	"fmt"

	"github.com/apernet/hysteria/extras/utils"
)

// convBandwidth handles both string and int types for bandwidth.
// When using string, it will be parsed as a bandwidth string with units.
// When using int, it will be parsed as a raw bandwidth in bytes per second.
// It does NOT support float types.
func convBandwidth(bw interface{}) (uint64, error) {
	switch bwT := bw.(type) {
	case string:
		return utils.StringToBps(bwT)
	case int:
		return uint64(bwT), nil
	default:
		return 0, fmt.Errorf("invalid type %T for bandwidth", bwT)
	}
}

type configError struct {
	Field string
	Err   error
}

func (e configError) Error() string {
	return fmt.Sprintf("invalid config: %s: %s", e.Field, e.Err)
}

func (e configError) Unwrap() error {
	return e.Err
}
