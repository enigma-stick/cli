package cmd

import (
	"enigma-cli/enigma"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign an arbitrary payload with a key on device",
	Args:  cobra.NoArgs,
	RunE:  sign,
}

func sign(cmd *cobra.Command, args []string) error {
	keyId, err := cmd.Flags().GetUint32("key-id")
	if err != nil {
		return err
	}
	if keyId == 0 {
		return fmt.Errorf("Invalid key ID")
	}

	var message []byte
	if cmd.Flags().Changed("message") && !cmd.Flags().Changed("in") {
		messageStr, err := cmd.Flags().GetString("message")
		if err != nil {
			return err
		}
		message = []byte(messageStr)
	} else if cmd.Flags().Changed("in") && !cmd.Flags().Changed("message") {
		path, err := cmd.Flags().GetString("in")
		if err != nil {
			return err
		}
		message, err = os.ReadFile(path)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("message OR in must be provided")
	}

	device, err := enigma.Open()
	if err != nil {
		return err
	}
	defer device.Close()

	signature, err := device.Sign(keyId, message)
	if err != nil {
		return err
	}

	if cmd.Flags().Changed("out") {
		path, err := cmd.Flags().GetString("out")
		if err != nil {
			return err
		}
		os.WriteFile(path, signature, 0644)
		fmt.Fprintf(cmd.OutOrStdout(), "Wrote signature to %s\n", path)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "%x\n", signature)
	}

	return nil
}
