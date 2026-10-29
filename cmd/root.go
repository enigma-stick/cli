package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "enigma-cli",
	Short: "Interact with Enigma Stick",
}

func init() {
	// status
	rootCmd.AddCommand(statusCmd)

	// authenticate
	authCmd.Flags().Bool("pin-stdin", false, "read PIN from standard input")
	rootCmd.AddCommand(authCmd)

	// lock
	rootCmd.AddCommand(lockCmd)

	// list-keys
	listKeysCmd.Flags().StringP("type", "t", "", "AES|HMAC|RSA|EC")
	listKeysCmd.Flags().StringP("usage", "u", "", "ENCRYPT|SIGN|DERIVE")
	listKeysCmd.Flags().StringP("label", "l", "", "Key label provided when generated")
	listKeysCmd.Flags().Uint32P("key-id", "k", 0, "Key ID (ignores other filters)")
	rootCmd.AddCommand(listKeysCmd)

	// generate-key
	generateCmd.Flags().StringP("type", "t", "", "AES|HMAC|RSA|EC")
	generateCmd.Flags().Uint16P("size", "s", 0, "Key size in bits")
	generateCmd.Flags().StringP("usage", "u", "", "ENCRYPT|SIGN|DERIVE")
	generateCmd.Flags().StringP("label", "l", "", "Key label")
	rootCmd.AddCommand(generateCmd)

	// destroy-key
	destroyCmd.Flags().Uint32P("key-id", "k", 0, "Key ID to destroy")
	destroyCmd.Flags().Bool("no-prompt", false, "Skip interactive confirmation prompt")
	rootCmd.AddCommand(destroyCmd)

	// export
	exportCmd.Flags().StringP("out", "o", "", "Public key output file")
	exportCmd.Flags().Uint32P("key-id", "k", 0, "Key ID")
	if err := exportCmd.MarkFlagRequired("key-id"); err != nil {
		panic(err)
	}
	exportCmd.Flags().String("format", "DER", "Public key format (DER|PEM)")
	if err := exportCmd.MarkFlagRequired("out"); err != nil {
		panic(err)
	}
	rootCmd.AddCommand(exportCmd)

	// sign
	signCmd.Flags().Uint32P("key-id", "k", 0, "Key ID")
	signCmd.Flags().String("message", "", "Message to be signed. Cannot be used with [in]")
	signCmd.Flags().StringP("in", "i", "", "Message input path. Cannot be used with [message]")
	signCmd.Flags().StringP("out", "o", "", "Signature output path. If ommitted, the signature is printed in base16")
	rootCmd.AddCommand(signCmd)

	// verify
	verifyCmd.Flags().Uint32P("key-id", "k", 0, "Key ID")
	verifyCmd.Flags().StringP("message", "m", "", "Message that was signed. Cannot be used with [in-message]")
	verifyCmd.Flags().String("in-message", "", "Message path. Cannot be used with [message]")
	verifyCmd.Flags().StringP("signature", "s", "", "Message signature. Cannot be used with [in-signature]")
	verifyCmd.Flags().String("in-signature", "", "Message signature path. Cannot be used with [signature]")
	rootCmd.AddCommand(verifyCmd)

	// encrypt
	encryptCmd.Flags().Uint32P("key-id", "k", 0, "Key ID")
	encryptCmd.Flags().StringP("plaintext", "p", "", "Plaintext to be encrypted. Cannot be used with [in]")
	encryptCmd.Flags().StringP("in", "i", "", "Path to plaintext. Cannot be used with [plaintext]")
	encryptCmd.Flags().StringP("out", "o", "", "Path to resulting ciphertext. If ommitted, the ciphertext is printed in base64")
	rootCmd.AddCommand(encryptCmd)

	// decrypt
	decryptCmd.Flags().Uint32P("key-id", "k", 0, "Key ID")
	decryptCmd.Flags().StringP("ciphertext", "c", "", "Ciphertext to be decrypted. Cannot be used with [in]")
	decryptCmd.Flags().StringP("in", "i", "", "Path to ciphertext. Cannot be used with [ciphertext]")
	decryptCmd.Flags().StringP("out", "o", "", "Path to resulting plaintext. If ommitted, the plaintext is printed in base64")
	rootCmd.AddCommand(decryptCmd)

	// ECDH
	ecdhCmd.Flags().Uint32P("key-id", "k", 0, "Key ID")
	ecdhCmd.Flags().StringP("in-public", "i", "", "Path to public key")
	ecdhCmd.Flags().String("in-form", "PEM", "Public key format")
	ecdhCmd.Flags().StringP("label", "l", "", "Resulting AES key label")
	ecdhCmd.Flags().String("out-salt", "", "Result path for salt calculated on-device")
	rootCmd.AddCommand(ecdhCmd)
}

func Execute() error {
	return rootCmd.Execute()
}
