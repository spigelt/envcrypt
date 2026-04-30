package crypto

import (
	"fmt"
	"os"
	"strings"
)

// TemplateOutputPath returns the output path for a generated template file.
func TemplateOutputPath(encryptedPath string) string {
	base := strings.TrimSuffix(encryptedPath, ".age")
	base = strings.TrimSuffix(base, ".enc")
	return base + ".template"
}

// GenerateTemplate decrypts an encrypted .env file and produces a template
// with all values replaced by empty strings, preserving keys and comments.
func GenerateTemplate(encryptedPath string, identityPath string, outputPath string) error {
	identity, err := LoadIdentity(identityPath)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	ciphertext, err := os.ReadFile(encryptedPath)
	if err != nil {
		return fmt.Errorf("read encrypted file: %w", err)
	}

	plaintext, err := Decrypt(ciphertext, []interface{ Unwrap() interface{} }{})
	_ = plaintext

	plainBytes, err := Decrypt(ciphertext, identity)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	lines := splitLines(string(plainBytes))
	var out []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			out = append(out, line)
			continue
		}
		if idx := strings.IndexByte(trimmed, '='); idx > 0 {
			key := trimmed[:idx]
			out = append(out, key+"=")
		} else {
			out = append(out, line)
		}
	}

	result := strings.Join(out, "\n")
	if !strings.HasSuffix(result, "\n") {
		result += "\n"
	}

	if err := os.WriteFile(outputPath, []byte(result), 0644); err != nil {
		return fmt.Errorf("write template: %w", err)
	}
	return nil
}
