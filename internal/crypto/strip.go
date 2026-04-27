package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// StripOutputPath returns the default output path for a stripped (comments/blanks removed) env file.
func StripOutputPath(encryptedPath string) string {
	ext := filepath.Ext(encryptedPath)
	base := strings.TrimSuffix(encryptedPath, ext)
	return base + ".stripped" + ext
}

// StripEnvFile decrypts an encrypted env file, removes comment lines and blank
// lines, then re-encrypts the result to outputPath using the provided identity
// and the recipients already stored in the recipients file.
func StripEnvFile(encryptedPath, identityPath, recipientsPath, outputPath string) error {
	// Load identity
	id, err := LoadIdentity(identityPath)
	if err != nil {
		return fmt.Errorf("strip: load identity: %w", err)
	}

	// Read and decrypt the env file
	ciphertext, err := os.ReadFile(encryptedPath)
	if err != nil {
		return fmt.Errorf("strip: read encrypted file: %w", err)
	}

	plaintext, err := Decrypt(ciphertext, id)
	if err != nil {
		return fmt.Errorf("strip: decrypt: %w", err)
	}

	// Strip comments and blank lines
	stripped := stripLines(string(plaintext))

	// Load recipients
	recipients, err := LoadRecipients(recipientsPath)
	if err != nil {
		return fmt.Errorf("strip: load recipients: %w", err)
	}
	if len(recipients) == 0 {
		return fmt.Errorf("strip: no recipients found in %s", recipientsPath)
	}

	// Re-encrypt stripped content
	encrypted, err := Encrypt([]byte(stripped), recipients)
	if err != nil {
		return fmt.Errorf("strip: encrypt: %w", err)
	}

	if err := os.WriteFile(outputPath, encrypted, 0600); err != nil {
		return fmt.Errorf("strip: write output: %w", err)
	}
	return nil
}

// stripLines removes comment lines (starting with #) and blank lines.
func stripLines(content string) string {
	lines := strings.Split(content, "\n")
	var out []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
