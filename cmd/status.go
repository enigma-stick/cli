package cmd

import (
	"enigma-cli/enigma"
	"fmt"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Get Enigma status",
	Args:  cobra.NoArgs,
	RunE:  status,
}

func status(cmd *cobra.Command, _args []string) error {
	device, err := enigma.Open()
	if err != nil {
		return err
	}
	defer device.Close()

	status, err := device.Status()
	if err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "STATUS; Token=%d, Session=%d\n", status.Token, status.Session)
	return nil
}
