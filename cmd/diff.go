package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"envcrypt/internal/crypto"
)

var (
	diffIdentityPath string
)

func init() {
	diffCmd := &cobra.Command{
		Use:   "diff <old.env.age> <new.env.age>",
		Short: "Show differences between two encrypted .env files",
		Long: `Decrypt and compare two encrypted .env files, showing which keys
were added, removed, or changed. Values are shown in plaintext so
ensure you are in a secure environment before running this command.`,
		Args: cobra.ExactArgs(2),
		RunE: runDiff,
	}

	diffCmd.Flags().StringVarP(
		&diffIdentityPath,
		"identity", "i",
		"",
		"Path to age identity file (default: ~/.config/envcrypt/identity.txt)",
	)

	rootCmd.AddCommand(diffCmd)
}

func runDiff(cmd *cobra.Command, args []string) error {
	oldPath := args[0]
	newPath := args[1]

	// Resolve identity path
	identityPath := diffIdentityPath
	if identityPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("could not determine home directory: %w", err)
		}
		identityPath = home + "/.config/envcrypt/identity.txt"
	}

	// Load identity for decryption
	identity, err := crypto.LoadIdentity(identityPath)
	if err != nil {
		return fmt.Errorf("failed to load identity from %s: %w", identityPath, err)
	}

	// Compute the diff between the two encrypted env files
	result, err := crypto.DiffEnvFiles(oldPath, newPath, identity)
	if err != nil {
		return fmt.Errorf("diff failed: %w", err)
	}

	// Print results
	if len(result.Added) == 0 && len(result.Removed) == 0 && len(result.Changed) == 0 {
		fmt.Println("No differences found.")
		return nil
	}

	if len(result.Added) > 0 {
		fmt.Println("Added:")
		for _, key := range result.Added {
			fmt.Printf("  + %s\n", key)
		}
	}

	if len(result.Removed) > 0 {
		fmt.Println("Removed:")
		for _, key := range result.Removed {
			fmt.Printf("  - %s\n", key)
		}
	}

	if len(result.Changed) > 0 {
		fmt.Println("Changed:")
		for _, entry := range result.Changed {
			fmt.Printf("  ~ %s: %q -> %q\n", entry.Key, entry.OldValue, entry.NewValue)
		}
	}

	return nil
}
