package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"envcrypt/internal/crypto"
)

var recipientsCmd = &cobra.Command{
	Use:   "recipients",
	Short: "Manage team recipients for encrypted .env files",
}

var addRecipientCmd = &cobra.Command{
	Use:   "add <public-key>",
	Short: "Add a recipient public key to the recipients file",
	Args:  cobra.ExactArgs(1),
	RunE:  runAddRecipient,
}

var listRecipientsCmd = &cobra.Command{
	Use:   "list",
	Short: "List all recipients in the recipients file",
	RunE:  runListRecipients,
}

var recipientsFile string

func init() {
	recipientsCmdFlags := recipientsCmd.PersistentFlags()
	recipientsCmdFlags.StringVarP(&recipientsFile, "file", "f", crypto.RecipientsFile, "path to recipients file")

	recipientsCmd.AddCommand(addRecipientCmd)
	recipientsCmd.AddCommand(listRecipientsCmd)
	rootCmd.AddCommand(recipientsCmd)
}

func runAddRecipient(cmd *cobra.Command, args []string) error {
	pubkey := args[0]
	if err := crypto.AddRecipient(recipientsFile, pubkey); err != nil {
		return fmt.Errorf("adding recipient: %w", err)
	}
	fmt.Fprintf(os.Stdout, "Added recipient %s to %s\n", pubkey, recipientsFile)
	return nil
}

func runListRecipients(cmd *cobra.Command, args []string) error {
	recipients, err := crypto.LoadRecipients(recipientsFile)
	if err != nil {
		return fmt.Errorf("loading recipients: %w", err)
	}
	fmt.Fprintf(os.Stdout, "Recipients in %s:\n", recipientsFile)
	for i, r := range recipients {
		fmt.Fprintf(os.Stdout, "  %d. %s\n", i+1, r)
	}
	return nil
}
