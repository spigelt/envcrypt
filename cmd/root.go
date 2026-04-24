package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "envcrypt",
	Short: "Encrypt and manage .env files using age encryption",
	Long: `envcrypt is a CLI tool for encrypting and managing .env files
using age encryption with team key sharing support.

Use 'envcrypt keygen' to generate a key pair, then 'envcrypt encrypt'
to encrypt your .env file for one or more recipients.`,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
