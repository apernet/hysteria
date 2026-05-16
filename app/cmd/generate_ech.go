package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/apernet/hysteria/app/v2/internal/utils"
)

var (
	echOutKey    string
	echOutConfig string
)

var generateECHKeyPairCmd = &cobra.Command{
	Use:   "ech-keypair <outer_server_name_indication>",
	Short: "Generate TLS ECH key pair",
	Args:  cobra.ExactArgs(1),
	Run:   runGenerateECHKeyPair,
}

func init() {
	generateECHKeyPairCmd.Flags().StringVar(&echOutKey, "outKey", "-", "output file for ECH keys (server), \"-\" for stdout")
	generateECHKeyPairCmd.Flags().StringVar(&echOutConfig, "outConfig", "-", "output file for ECH configs (client), \"-\" for stdout")
	generateCmd.AddCommand(generateECHKeyPairCmd)
}

func runGenerateECHKeyPair(cmd *cobra.Command, args []string) {
	configPem, keyPem, err := utils.ECHKeygen(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
	if err := writeOutput(echOutConfig, configPem); err != nil {
		fmt.Fprintln(os.Stderr, "Error writing config:", err)
		os.Exit(1)
	}
	if err := writeOutput(echOutKey, keyPem); err != nil {
		fmt.Fprintln(os.Stderr, "Error writing key:", err)
		os.Exit(1)
	}
}

func writeOutput(path, content string) error {
	if path == "-" {
		_, err := os.Stdout.WriteString(content)
		return err
	}
	return os.WriteFile(path, []byte(content), 0600)
}
