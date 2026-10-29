package cmd

import (
	"encoding/base64"
	"enigma-cli/enigma"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt ciphertext on device",
	Args:  cobra.NoArgs,
	RunE:  decrypt,
}

func decrypt(cmd *cobra.Command, args []string) error {
	keyId, err := cmd.Flags().GetUint32("key-id")
	if err != nil {
		return err
	}
	if keyId == 0 {
		return fmt.Errorf("Invalid key ID")
	}

	var ciphertext []byte
	if cmd.Flags().Changed("ciphertext") && !cmd.Flags().Changed("in") {
		ciphertextStr, err := cmd.Flags().GetString("ciphertext")
		if err != nil {
			return err
		}
		ciphertext, err = base64.StdEncoding.DecodeString(ciphertextStr)
		if err != nil {
			return err
		}
	} else if cmd.Flags().Changed("in") && !cmd.Flags().Changed("plaintext") {
		path, err := cmd.Flags().GetString("in")
		if err != nil {
			return err
		}
		ciphertext, err = os.ReadFile(path)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("ciphertext OR in must be provided")
	}

	device, err := enigma.Open()
	if err != nil {
		return err
	}
	defer device.Close()

	plaintext, err := device.Decrypt(keyId, ciphertext)
	if err != nil {
		return err
	}

	if cmd.Flags().Changed("out") {
		path, err := cmd.Flags().GetString("out")
		if err != nil {
			return err
		}
		os.WriteFile(path, plaintext, 0644)
		fmt.Fprintf(cmd.OutOrStdout(), "Wrote plaintext to %s\n", path)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n", plaintext)
	}

	return nil
}
