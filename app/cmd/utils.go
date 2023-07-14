package cmd

import (
	"fmt"
	"os"

	"github.com/apernet/hysteria/extras/utils"
	"github.com/mdp/qrterminal/v3"
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

func printQR(str string) {
	qrterminal.GenerateWithConfig(str, qrterminal.Config{
		Level:     qrterminal.L,
		Writer:    os.Stdout,
		BlackChar: qrterminal.BLACK,
		WhiteChar: qrterminal.WHITE,
	})
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
