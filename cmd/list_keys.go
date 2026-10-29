package cmd

import (
	"enigma-cli/enigma"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var listKeysCmd = &cobra.Command{
	Use:   "list-keys",
	Short: "List existing keys on the device",
	Args:  cobra.NoArgs,
	RunE:  listKeys,
}

func listKeys(cmd *cobra.Command, args []string) error {
	keyFilter := &enigma.KeyFilter{
		Type:  nil,
		Usage: nil,
		Label: nil,
		ID:    nil,
	}

	if cmd.Flags().Changed("id") {
		val, err := cmd.Flags().GetUint32("id")
		if err != nil {
			return err
		}

		keyFilter.ID = &val
	}

	if cmd.Flags().Changed("type") {
		strVal, err := cmd.Flags().GetString("type")
		if err != nil {
			return nil
		}

		val, err := enigma.ParseKeyType(strVal)
		if err != nil {
			return nil
		}

		keyFilter.Type = &val
	}

	if cmd.Flags().Changed("usage") {
		strVal, err := cmd.Flags().GetString("usage")
		if err != nil {
			return nil
		}

		val, err := enigma.ParseKeyUsage(strVal)
		if err != nil {
			return nil
		}

		keyFilter.Usage = &val
	}

	if cmd.Flags().Changed("label") {
		val, err := cmd.Flags().GetString("label")
		if err != nil {
			return err
		}

		keyFilter.Label = &val
	}

	device, err := enigma.Open()
	if err != nil {
		return err
	}
	defer device.Close()

	keys, err := device.ListKeys(keyFilter)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 1, ' ', 0)
	fmt.Fprintln(w, "ID\tLabel\tType\tSize\tUsage\tCreated")
	for _, k := range keys {
		fmt.Fprintf(w, "%#x\t%s\t%s\t%d\t%s\t%s\n", k.ID, k.Label, k.Type.String(), k.Size, k.Usage.String(), time.Unix(int64(k.CreatedAt), 0))
	}
	w.Flush()

	return nil
}
