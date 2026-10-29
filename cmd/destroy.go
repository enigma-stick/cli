package cmd

import (
	"enigma-cli/enigma"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var destroyCmd = &cobra.Command{
	Use:   "destroy-key",
	Short: "Permanently destroy device key",
	Args:  cobra.NoArgs,
	RunE:  destroy,
}

func destroy(cmd *cobra.Command, args []string) error {
	skipPrompt, err := cmd.Flags().GetBool("no-prompt")
	if err != nil {
		return err
	}

	keyId, err := cmd.Flags().GetUint32("key-id")
	if err != nil {
		return err
	}
	if keyId == 0 {
		return fmt.Errorf("Invalid Key ID")
	}

	if !skipPrompt {
		fmt.Fprintf(cmd.OutOrStdout(), "Are you sure you want to destroy this key? This action cannot be undone [y/N] ")

		var confirm string
		_, err := fmt.Fscanln(cmd.InOrStdin(), &confirm)
		if err != nil {
			return err
		}

		if strings.ToUpper(confirm) != "Y" {
			fmt.Fprintln(cmd.OutOrStdout(), "Cancelled operation")
			return nil
		}
	}

	device, err := enigma.Open()
	if err != nil {
		return err
	}
	defer device.Close()

	err = device.DestroyKey(keyId)
	if err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Destroyed key %#x\n", keyId)
	return nil
}
