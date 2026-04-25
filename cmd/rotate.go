package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"envcrypt/internal/crypto"
)

var (
	rotateEnvFile      string
	rotateIdentityFile string
)

func init() {
	rotateCmd := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate the encryption key for an env file",
		Long: `Generate a new age identity, re-encrypt the env file so it is
accessible with the new key, back up the old identity, and save
the new identity in place of the old one.`,
		RunE: runRotate,
	}

	rotateCmd.Flags().StringVarP(&rotateEnvFile, "env-file", "e", ".env.age", "Path to the encrypted env file")
	rotateCmd.Flags().StringVarP(&rotateIdentityFile, "identity", "i", "", "Path to the age identity file (required)")
	_ = rotateCmd.MarkFlagRequired("identity")

	rootCmd.AddCommand(rotateCmd)
}

func runRotate(cmd *cobra.Command, args []string) error {
	fmt.Fprintf(os.Stderr, "Rotating key for %s using identity %s\n", rotateEnvFile, rotateIdentityFile)

	if err := crypto.RotateKey(rotateEnvFile, rotateIdentityFile); err != nil {
		return fmt.Errorf("key rotation failed: %w", err)
	}

	fmt.Println("Key rotation complete.")
	fmt.Println("A backup of the old identity has been saved alongside the identity file.")
	fmt.Println("Remember to remove the old recipient from the recipients file if needed.")
	return nil
}
