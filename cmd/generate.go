package cmd

import (
	"enigma-cli/enigma"
	"fmt"

	"github.com/spf13/cobra"
)

var generateCmd = &cobra.Command{
	Use:   "generate-key",
	Short: "Generate a key on-device",
	Args:  cobra.NoArgs,
	RunE:  generate,
}

func generate(cmd *cobra.Command, args []string) error {
	kindStr, err := cmd.Flags().GetString("type")
	if err != nil {
		return err
	}
	kind, err := enigma.ParseKeyType(kindStr)
	if err != nil {
		return err
	}

	size, err := cmd.Flags().GetUint16("size")
	if err != nil {
		return err
	}

	usageStr, err := cmd.Flags().GetString("usage")
	if err != nil {
		return err
	}
	usage, err := enigma.ParseKeyUsage(usageStr)
	if err != nil {
		return err
	}

	label, err := cmd.Flags().GetString("label")
	if err != nil {
		return err
	}

	device, err := enigma.Open()
	if err != nil {
		return err
	}
	defer device.Close()

	keyId, err := device.GenerateKey(kind, usage, size, label)
	if err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Generated key: %#x", keyId)
	return nil
}
