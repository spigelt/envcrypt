package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"envcrypt/internal/crypto"
)

var auditCmd = &cobra.Command{
	Use:   "audit [file]",
	Short: "Show the audit log for an encrypted env file",
	Args:  cobra.ExactArgs(1),
	RunE:  runAudit,
}

func init() {
	rootCmd.AddCommand(auditCmd)
}

func runAudit(cmd *cobra.Command, args []string) error {
	envFile := args[0]
	logPath := crypto.AuditLogPath(envFile)

	entries, err := crypto.ReadAuditLog(logPath)
	if err != nil {
		return fmt.Errorf("reading audit log: %w", err)
	}

	if len(entries) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "No audit entries found for %s\n", envFile)
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIMESTAMP\tOPERATION\tFILE\tUSER\tDETAILS")
	for _, e := range entries {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			e.Timestamp.Format("2006-01-02 15:04:05"),
			e.Operation,
			e.File,
			e.User,
			e.Details,
		)
	}
	return w.Flush()
}
