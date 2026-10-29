package cmd

import (
	"encoding/base64"
	"enigma-cli/enigma"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt arbitrary plaintext on device",
	Args:  cobra.NoArgs,
	RunE:  encrypt,
}

func encrypt(cmd *cobra.Command, args []string) error {
	keyId, err := cmd.Flags().GetUint32("key-id")
	if err != nil {
		return err
	}
	if keyId == 0 {
		return fmt.Errorf("Invalid key ID")
	}

	var plaintext []byte
	if cmd.Flags().Changed("plaintext") && !cmd.Flags().Changed("in") {
		plaintextStr, err := cmd.Flags().GetString("plaintext")
		if err != nil {
			return err
		}
		plaintext = []byte(plaintextStr)
	} else if cmd.Flags().Changed("in") && !cmd.Flags().Changed("plaintext") {
		path, err := cmd.Flags().GetString("in")
		if err != nil {
			return err
		}
		plaintext, err = os.ReadFile(path)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("plaintext OR in must be provided")
	}

	device, err := enigma.Open()
	if err != nil {
		return err
	}
	defer device.Close()

	ciphertext, err := device.Encrypt(keyId, plaintext)
	if err != nil {
		return err
	}

	if cmd.Flags().Changed("out") {
		path, err := cmd.Flags().GetString("out")
		if err != nil {
			return err
		}
		os.WriteFile(path, ciphertext, 0644)
		fmt.Fprintf(cmd.OutOrStdout(), "Wrote ciphertext to %s\n", path)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n", base64.StdEncoding.EncodeToString(ciphertext))
	}

	return nil
}
