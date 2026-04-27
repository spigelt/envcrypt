package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CopyOutputPath returns the output path for a copied env file.
// If destDir is empty, the copy is placed alongside the source with a new environment suffix.
func CopyOutputPath(srcPath, destEnv string) string {
	dir := filepath.Dir(srcPath)
	base := filepath.Base(srcPath)

	// Strip existing .env.<something>.age or .env.age pattern
	stripped := strings.TrimSuffix(base, filepath.Ext(base)) // remove .age
	stripped = strings.TrimSuffix(stripped, filepath.Ext(stripped)) // remove .<env>

	return filepath.Join(dir, stripped+"."+destEnv+".age")
}

// CopyEnvFile decrypts srcPath using the identity at identityPath,
// then re-encrypts the plaintext to destPath using the recipients file
// found alongside destPath (or falls back to the source recipients).
func CopyEnvFile(srcPath, destEnv, identityPath string) (string, error) {
	identity, err := LoadIdentity(identityPath)
	if err != nil {
		return "", fmt.Errorf("load identity: %w", err)
	}

	// Decrypt source
	plaintext, err := Decrypt(srcPath, identity)
	if err != nil {
		return "", fmt.Errorf("decrypt source: %w", err)
	}

	destPath := CopyOutputPath(srcPath, destEnv)

	if _, err := os.Stat(destPath); err == nil {
		return "", fmt.Errorf("destination already exists: %s", destPath)
	}

	// Determine recipients file: prefer one next to dest, fall back to source dir
	srcDir := filepath.Dir(srcPath)
	recsPath := filepath.Join(srcDir, ".recipients")
	if _, err := os.Stat(recsPath); os.IsNotExist(err) {
		return "", fmt.Errorf("recipients file not found at %s", recsPath)
	}

	recipients, err := LoadRecipients(recsPath)
	if err != nil {
		return "", fmt.Errorf("load recipients: %w", err)
	}

	if err := Encrypt(destPath, []byte(plaintext), recipients); err != nil {
		return "", fmt.Errorf("encrypt destination: %w", err)
	}

	return destPath, nil
}
