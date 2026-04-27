package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"envcrypt/internal/crypto"
)

var renameIdentityPath string

func init() {
	renameCmd := &cobra.Command{
		Use:   "rename <encrypted-file> <new-name>",
		Short: "Rename an encrypted .env file",
		Args:  cobra.ExactArgs(2),
		RunE:  runRename,
	}
	renameCmd.Flags().StringVarP(&renameIdentityPath, "identity", "i",
		filepath.Join(os.Getenv("HOME"), ".config", "envcrypt", "identity.age"),
		"Path to age identity file")
	rootCmd.AddCommand(renameCmd)
}

func runRename(cmd *cobra.Command, args []string) error {
	oldPath := args[0]
	newName := args[1]

	newPath, err := crypto.RenameEnvFile(oldPath, newName, renameIdentityPath)
	if err != nil {
		return fmt.Errorf("rename failed: %w", err)
	}

	fmt.Printf("Renamed: %s -> %s\n", oldPath, newPath)
	return nil
}
