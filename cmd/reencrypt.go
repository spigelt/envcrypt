package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"envcrypt/internal/crypto"
)

var (
	reencryptIdentityPath   string
	reencryptRecipientsPath string
)

func init() {
	reencryptCmd := &cobra.Command{
		Use:   "reencrypt [encrypted-file]",
		Short: "Re-encrypt an .env.age file for all current recipients",
		Long: `Decrypt the given .env.age file using your identity and re-encrypt it
for all recipients listed in the recipients file. Useful after adding or
removing team members.`,
		Args: cobra.ExactArgs(1),
		RunE: runReencrypt,
	}

	reencryptCmd.Flags().StringVarP(
		&reencryptIdentityPath, "identity", "i",
		defaultIdentityPath(),
		"Path to your age identity file",
	)
	reencryptCmd.Flags().StringVarP(
		&reencryptRecipientsPath, "recipients", "r",
		".env.recipients",
		"Path to the recipients file",
	)

	rootCmd.AddCommand(reencryptCmd)
}

func runReencrypt(cmd *cobra.Command, args []string) error {
	encryptedFile := args[0]

	if _, err := os.Stat(encryptedFile); os.IsNotExist(err) {
		return fmt.Errorf("encrypted file not found: %s", encryptedFile)
	}

	fmt.Printf("Re-encrypting %s for all recipients in %s...\n", encryptedFile, reencryptRecipientsPath)

	if err := crypto.ReencryptEnvFile(encryptedFile, reencryptIdentityPath, reencryptRecipientsPath); err != nil {
		return fmt.Errorf("reencrypt failed: %w", err)
	}

	outPath := crypto.ReencryptOutputPath(encryptedFile)
	fmt.Printf("Successfully re-encrypted to %s\n", outPath)
	return nil
}
