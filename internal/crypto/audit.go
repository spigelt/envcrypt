package crypto

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// AuditEntry represents a single audit log entry.
type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Operation string    `json:"operation"`
	File      string    `json:"file"`
	User      string    `json:"user,omitempty"`
	Details   string    `json:"details,omitempty"`
}

// AuditLogPath returns the path to the audit log file for a given env file.
func AuditLogPath(envFile string) string {
	dir := filepath.Dir(envFile)
	base := filepath.Base(envFile)
	return filepath.Join(dir, "."+base+".audit.log")
}

// AppendAuditEntry appends a new entry to the audit log.
func AppendAuditEntry(logPath string, entry AuditEntry) error {
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("opening audit log: %w", err)
	}
	defer f.Close()

	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshalling audit entry: %w", err)
	}
	_, err = fmt.Fprintf(f, "%s\n", line)
	return err
}

// ReadAuditLog reads all audit entries from the log file.
func ReadAuditLog(logPath string) ([]AuditEntry, error) {
	data, err := os.ReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading audit log: %w", err)
	}

	var entries []AuditEntry
	for _, line := range splitLines(string(data)) {
		if line == "" {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, fmt.Errorf("parsing audit entry: %w", err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// splitLines splits a string into lines.
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
