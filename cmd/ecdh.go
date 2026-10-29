package cmd

import (
	"encoding/pem"
	"enigma-cli/enigma"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var ecdhCmd = &cobra.Command{
	Use:   "ecdh",
	Short: "Perform ECDH and HKDF to generate shared AES key",
	Args:  cobra.NoArgs,
	RunE:  ecdh,
}

func ecdh(cmd *cobra.Command, args []string) error {
	keyId, err := cmd.Flags().GetUint32("key-id")
	if err != nil {
		return err
	}
	if keyId == 0 {
		return fmt.Errorf("Invalid key ID")
	}

	publicKeyPath, err := cmd.Flags().GetString("in-public")
	if err != nil {
		return err
	}
	publicKeyFormat, err := cmd.Flags().GetString("in-form")
	if err != nil {
		return err
	}

	label, err := cmd.Flags().GetString("label")
	if err != nil {
		return err
	}

	var publicKey []byte
	switch publicKeyFormat {
	case "DER":
		publicKey, err = os.ReadFile(publicKeyPath)
		if err != nil {
			return err
		}
		break
	case "PEM":
		bytes, err := os.ReadFile(publicKeyPath)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(bytes)
		publicKey = block.Bytes
		break
	default:
		return fmt.Errorf("Invalid public key format")
	}

	device, err := enigma.Open()
	if err != nil {
		return err
	}
	defer device.Close()

	result, err := device.ECDH(keyId, publicKey, label)
	if err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Key ID: %#x\n", result.KeyID)

	if cmd.Flags().Changed("out-salt") {
		pathName, err := cmd.Flags().GetString("out-salt")
		if err != nil {
			return err
		}
		err = os.WriteFile(pathName, result.Salt, 0644)
		if err != nil {
			return err
		}
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Salt: %x\n", result.Salt)
	}

	return nil
}
