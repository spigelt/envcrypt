package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"envcrypt/internal/crypto"
)

var lintIdentityPath string

func init() {
	lintCmd := &cobra.Command{
		Use:   "lint [file.env.age]",
		Short: "Lint a decrypted .env file for style issues",
		Args:  cobra.ExactArgs(1),
		RunE:  runLint,
	}
	lintCmd.Flags().StringVarP(&lintIdentityPath, "identity", "i", "", "Path to age identity file (required)")
	_ = lintCmd.MarkFlagRequired("identity")
	rootCmd.AddCommand(lintCmd)
}

func runLint(cmd *cobra.Command, args []string) error {
	encPath := args[0]

	if _, err := os.Stat(encPath); os.IsNotExist(err) {
		return fmt.Errorf("file not found: %s", encPath)
	}

	issues, err := crypto.LintEnvFile(encPath, lintIdentityPath)
	if err != nil {
		return fmt.Errorf("lint failed: %w", err)
	}

	base := filepath.Base(encPath)

	if len(issues) == 0 {
		fmt.Printf("%s: no issues found\n", base)
		return nil
	}

	fmt.Fprintf(os.Stderr, "%s: %d issue(s) found\n", base, len(issues))
	for _, issue := range issues {
		fmt.Fprintf(os.Stderr, "  %s\n", issue)
	}
	// Exit with non-zero so CI pipelines can catch lint failures.
	os.Exit(1)
	return nil
}
