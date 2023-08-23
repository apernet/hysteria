package utils

import (
	"os"

	"github.com/mdp/qrterminal/v3"
)

func PrintQR(str string) {
	qrterminal.GenerateWithConfig(str, qrterminal.Config{
		Level:     qrterminal.L,
		Writer:    os.Stdout,
		BlackChar: qrterminal.BLACK,
		WhiteChar: qrterminal.WHITE,
	})
}
