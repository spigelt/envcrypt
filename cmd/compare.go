package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"envcrypt/internal/crypto"
)

var compareIdentityPath string
var compareSave bool

func init() {
	compareCmd := &cobra.Command{
		Use:   "compare <file-a.env.age> <file-b.env.age>",
		Short: "Compare two encrypted env files and show key differences",
		Args:  cobra.ExactArgs(2),
		RunE:  runCompare,
	}
	compareCmd.Flags().StringVarP(&compareIdentityPath, "identity", "i", "", "Path to age identity file (required)")
	compareCmd.Flags().BoolVar(&compareSave, "save", false, "Save compare report to a .compare.txt file")
	_ = compareCmd.MarkFlagRequired("identity")
	rootCmd.AddCommand(compareCmd)
}

func runCompare(cmd *cobra.Command, args []string) error {
	fileA := args[0]
	fileB := args[1]

	result, err := crypto.CompareEnvFiles(fileA, fileB, compareIdentityPath)
	if err != nil {
		return fmt.Errorf("compare: %w", err)
	}

	output := crypto.FormatCompareResult(fileA, fileB, result)
	fmt.Print(output)

	if compareSave {
		outPath := crypto.CompareOutputPath(fileA, fileB)
		if err := os.WriteFile(outPath, []byte(output), 0o644); err != nil {
			return fmt.Errorf("save report: %w", err)
		}
		fmt.Printf("Report saved to %s\n", outPath)
	}

	return nil
}
