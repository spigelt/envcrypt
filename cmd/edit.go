package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"envcrypt/internal/crypto"
)

var (
	editIdentityPath   string
	editRecipientsPath string
)

func init() {
	editCmd := &cobra.Command{
		Use:   "edit [file.enc]",
		Short: "Decrypt, edit, and re-encrypt an env file in your $EDITOR",
		Args:  cobra.ExactArgs(1),
		RunE:  runEdit,
	}

	home, _ := os.UserHomeDir()
	defaultIdentity := filepath.Join(home, ".config", "envcrypt", "identity.txt")

	editCmd.Flags().StringVarP(&editIdentityPath, "identity", "i", defaultIdentity, "Path to age identity file")
	editCmd.Flags().StringVarP(&editRecipientsPath, "recipients", "r", ".envcrypt-recipients", "Path to recipients file")

	rootCmd.AddCommand(editCmd)
}

func runEdit(cmd *cobra.Command, args []string) error {
	encPath := args[0]

	if _, err := os.Stat(encPath); os.IsNotExist(err) {
		return fmt.Errorf("encrypted file not found: %s", encPath)
	}

	if err := crypto.EditEnvFile(encPath, editIdentityPath, editRecipientsPath); err != nil {
		return fmt.Errorf("edit failed: %w", err)
	}

	fmt.Printf("✓ Saved re-encrypted file: %s\n", encPath)
	return nil
}
