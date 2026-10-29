package cmd

import (
	"enigma-cli/enigma"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify HMAC signature",
	Args:  cobra.NoArgs,
	RunE:  verify,
}

func verify(cmd *cobra.Command, args []string) error {
	keyId, err := cmd.Flags().GetUint32("key-id")
	if err != nil {
		return err
	}
	if keyId == 0 {
		return fmt.Errorf("Invalid key ID")
	}

	var message []byte
	if cmd.Flags().Changed("message") && !cmd.Flags().Changed("in-message") {
		messageStr, err := cmd.Flags().GetString("message")
		if err != nil {
			return err
		}
		message = []byte(messageStr)
	} else if cmd.Flags().Changed("in-message") && !cmd.Flags().Changed("message") {
		messagePath, err := cmd.Flags().GetString("in-message")
		if err != nil {
			return err
		}
		message, err = os.ReadFile(messagePath)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("Must provide in-message OR message")
	}

	var signature []byte
	if cmd.Flags().Changed("signature") && !cmd.Flags().Changed("in-signature") {
		signatureStr, err := cmd.Flags().GetString("signature")
		if err != nil {
			return err
		}
		signature = []byte(signatureStr)
	} else if cmd.Flags().Changed("in-signature") && !cmd.Flags().Changed("signature") {
		signaturePath, err := cmd.Flags().GetString("in-signature")
		if err != nil {
			return err
		}
		signature, err = os.ReadFile(signaturePath)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("Must provide in-signature OR signature")
	}

	device, err := enigma.Open()
	if err != nil {
		return err
	}
	defer device.Close()

	ok, err := device.Verify(keyId, message, signature)
	if err != nil {
		return err
	}

	if !ok {
		return fmt.Errorf("Invalid signature")
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Verified: OK")
	return nil
}

