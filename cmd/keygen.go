package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/yourorg/envcrypt/internal/crypto"
)

var (
	keygenOutputDir string
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a new age identity (key pair)",
	Long: `Generate a new age X25519 identity and save the private key to disk.

The public key will be printed to stdout for sharing with teammates.
The private key is saved to ~/.envcrypt/identity.age by default.`,
	RunE: runKeygen,
}

func init() {
	homeDir, _ := os.UserHomeDir()
	defaultKeyDir := filepath.Join(homeDir, crypto.DefaultKeyDir)

	keygenCmd.Flags().StringVarP(
		&keygenOutputDir, "output", "o", defaultKeyDir,
		"Directory to store the generated identity file",
	)

	rootCmd.AddCommand(keygenCmd)
}

func runKeygen(cmd *cobra.Command, args []string) error {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		return fmt.Errorf("generating identity: %w", err)
	}

	keyPath, err := crypto.SaveIdentity(id, keygenOutputDir)
	if err != nil {
		return fmt.Errorf("saving identity: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Public key:   %s\n", id.PublicKey())
	fmt.Fprintf(cmd.OutOrStdout(), "Identity file: %s\n", keyPath)
	fmt.Fprintln(cmd.OutOrStdout(), "\nShare your public key with teammates so they can encrypt secrets for you.")
	fmt.Fprintln(cmd.OutOrStdout(), "Keep your identity file private — never commit it to version control.")

	return nil
}
