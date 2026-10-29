package cmd

import (
	"enigma-cli/enigma"

	"github.com/spf13/cobra"
)

var lockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Lock the device",
	Args:  cobra.NoArgs,
	RunE:  lock,
}

func lock(cmd *cobra.Command, args []string) error {
	device, err := enigma.Open()
	if err != nil {
		return err
	}
	defer device.Close()

	return device.Lock()
}
