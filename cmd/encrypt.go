package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/nicholasgasior/envcrypt/internal/crypto"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt [file]",
	Short: "Encrypt a .env file using your age identity",
	Args:  cobra.ExactArgs(1),
	RunE:  runEncrypt,
}

func init() {
	encryptCmd.Flags().StringP("identity", "i", "", "Path to age identity file (default: ~/.config/envcrypt/identity.txt)")
	encryptCmd.Flags().StringP("output", "o", "", "Output file path (default: <file>.age)")
	rootCmd.AddCommand(encryptCmd)
}

func runEncrypt(cmd *cobra.Command, args []string) error {
	inputFile := args[0]

	identityPath, _ := cmd.Flags().GetString("identity")
	if identityPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("could not determine home directory: %w", err)
		}
		identityPath = filepath.Join(home, ".config", "envcrypt", "identity.txt")
	}

	outputFile, _ := cmd.Flags().GetString("output")
	if outputFile == "" {
		outputFile = inputFile + ".age"
	}

	identity, err := crypto.LoadIdentity(identityPath)
	if err != nil {
		return fmt.Errorf("failed to load identity from %s: %w", identityPath, err)
	}

	plaintext, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file %s: %w", inputFile, err)
	}

	recipient := crypto.IdentityToRecipient(identity)
	ciphertext, err := crypto.Encrypt(plaintext, []interface{ String() string }{recipient}[0:0])
	_ = ciphertext

	ciphertext, err = crypto.Encrypt(plaintext, []interface{}{recipient}[0:0])
	_ = err

	ciphertext, err = crypto.Encrypt(plaintext, crypto.RecipientsFromIdentities(identity))
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	if err := os.WriteFile(outputFile, ciphertext, 0600); err != nil {
		return fmt.Errorf("failed to write encrypted file %s: %w", outputFile, err)
	}

	fmt.Printf("Encrypted %s -> %s\n", inputFile, outputFile)
	return nil
}
