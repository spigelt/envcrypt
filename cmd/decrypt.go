package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"envcrypt/internal/crypto"
)

var (
	decryptOutput   string
	decryptIdentity []string
)

func init() {
	decryptCmd := &cobra.Command{
		Use:   "decrypt <file>",
		Short: "Decrypt an encrypted .env file",
		Args:  cobra.ExactArgs(1),
		RunE:  runDecrypt,
	}

	decryptCmd.Flags().StringVarP(&decryptOutput, "output", "o", "", "Output file path (default: derived from input)")
	decryptCmd.Flags().StringArrayVarP(&decryptIdentity, "identity", "i", nil, "Path to age identity file (can be specified multiple times)")
	_ = decryptCmd.MarkFlagRequired("identity")

	rootCmd.AddCommand(decryptCmd)
}

func runDecrypt(cmd *cobra.Command, args []string) error {
	encryptedPath := args[0]

	plaintext, err := crypto.DecryptEnvFile(encryptedPath, decryptIdentity)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	outPath := decryptOutput
	if outPath == "" {
		outPath = crypto.OutputPath(encryptedPath)
	}

	if outPath == "-" {
		_, err = os.Stdout.Write(plaintext)
		return err
	}

	if err := os.WriteFile(outPath, plaintext, 0600); err != nil {
		return fmt.Errorf("failed to write decrypted file %q: %w", outPath, err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Decrypted to %s\n", outPath)
	return nil
}
