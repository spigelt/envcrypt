package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ExportPlaintext decrypts an encrypted .env file and writes the plaintext
// to the given output path (or stdout if outputPath is "-").
func ExportPlaintext(encryptedPath, identityPath, outputPath string) error {
	identity, err := LoadIdentity(identityPath)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	ciphertext, err := os.ReadFile(encryptedPath)
	if err != nil {
		return fmt.Errorf("read encrypted file: %w", err)
	}

	plaintext, err := Decrypt(ciphertext, identity)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	if outputPath == "-" {
		_, err = os.Stdout.Write(plaintext)
		return err
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	if err := os.WriteFile(outputPath, plaintext, 0600); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}

	return nil
}

// ExportOutputPath returns the default plaintext output path for a given
// encrypted env file path by stripping the ".age" suffix if present.
func ExportOutputPath(encryptedPath string) string {
	if strings.HasSuffix(encryptedPath, ".age") {
		return strings.TrimSuffix(encryptedPath, ".age")
	}
	return encryptedPath + ".plain"
}
