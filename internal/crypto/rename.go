package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RenameOutputPath returns the output path for a renamed env file.
// It replaces the base name while preserving the directory and .enc extension.
func RenameOutputPath(oldPath, newName string) string {
	dir := filepath.Dir(oldPath)
	ext := filepath.Ext(oldPath)
	if ext == "" {
		ext = ".enc"
	}
	base := strings.TrimSuffix(newName, ext)
	return filepath.Join(dir, base+ext)
}

// RenameEnvFile renames an encrypted env file to a new name within the same
// directory, updating the audit log to record the operation.
func RenameEnvFile(oldPath, newName, identityPath string) (string, error) {
	if _, err := os.Stat(oldPath); os.IsNotExist(err) {
		return "", fmt.Errorf("encrypted file not found: %s", oldPath)
	}

	newPath := RenameOutputPath(oldPath, newName)

	if oldPath == newPath {
		return "", fmt.Errorf("new name is the same as the current name")
	}

	if _, err := os.Stat(newPath); err == nil {
		return "", fmt.Errorf("destination already exists: %s", newPath)
	}

	if err := os.Rename(oldPath, newPath); err != nil {
		return "", fmt.Errorf("rename failed: %w", err)
	}

	auditPath := AuditLogPath(filepath.Dir(newPath))
	_ = AppendAuditEntry(auditPath, fmt.Sprintf("rename: %s -> %s", filepath.Base(oldPath), filepath.Base(newPath)))

	return newPath, nil
}
