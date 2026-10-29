package cmd

import (
	"encoding/pem"
	"enigma-cli/enigma"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export public key material from the device",
	Args:  cobra.NoArgs,
	RunE:  export,
}

func export(cmd *cobra.Command, args []string) error {
	format, err := cmd.Flags().GetString("format")
	if err != nil {
		return err
	}

	switch format {
	case "DER", "PEM":
	default:
		return fmt.Errorf("invalid --format %q: want DER or PEM", format)
	}

	keyId, err := cmd.Flags().GetUint32("key-id")
	if err != nil {
		return err
	}
	if keyId == 0 {
		return fmt.Errorf("Invalid key ID")
	}

	outPath, err := cmd.Flags().GetString("out")
	if err != nil {
		return err
	}

	device, err := enigma.Open()
	if err != nil {
		return err
	}
	defer device.Close()

	bytes, err := device.ExportPublicKey(keyId)
	if err != nil {
		return err
	}

	if format == "PEM" {
		bytes = pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: bytes,
		})
	}

	err = os.WriteFile(outPath, bytes, 0644)
	if err != nil {
		return err
	}

	return nil
}
