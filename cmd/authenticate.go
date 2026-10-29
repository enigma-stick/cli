package cmd

import (
	"enigma-cli/enigma"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var authCmd = &cobra.Command{
	Use:   "authenticate",
	Short: "Authenticate the device. Auth is global.",
	Args:  cobra.NoArgs,
	RunE:  authenticate,
}

func authenticate(cmd *cobra.Command, args []string) error {
	pinStdin, err := cmd.Flags().GetBool("pin-stdin")
	if err != nil {
		return err
	}

	var pin string = ""

	if pinStdin {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		pin = string(data)
	} else {
		fmt.Fprint(cmd.OutOrStdout(), "PIN: ")
		pinBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprint(cmd.OutOrStdout(), "\n")
		if err != nil {
			return err
		}
		pin = string(pinBytes)
	}

	device, err := enigma.Open()
	if err != nil {
		return err
	}
	defer device.Close()

	err = device.Authenticate(pin)
	if err != nil {
		return err
	}

	fmt.Fprint(cmd.OutOrStdout(), "Device authenticated successfully\n")
	return nil
}
