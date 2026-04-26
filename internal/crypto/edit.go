package crypto

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// EditEnvFile decrypts an encrypted .env file to a temp file, opens it in
// the user's $EDITOR, then re-encrypts the result back to the original path.
func EditEnvFile(encPath string, identityPath string, recipientsPath string) error {
	identity, err := LoadIdentity(identityPath)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	recipients, err := LoadRecipients(recipientsPath)
	if err != nil {
		return fmt.Errorf("load recipients: %w", err)
	}

	ciphertext, err := os.ReadFile(encPath)
	if err != nil {
		return fmt.Errorf("read encrypted file: %w", err)
	}

	plaintext, err := Decrypt(ciphertext, identity)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "envcrypt-edit-*.env")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(plaintext); err != nil {
		tmpFile.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	tmpFile.Close()

	if err := openEditor(tmpPath); err != nil {
		return fmt.Errorf("editor: %w", err)
	}

	updated, err := os.ReadFile(tmpPath)
	if err != nil {
		return fmt.Errorf("read edited file: %w", err)
	}

	newCiphertext, err := Encrypt(updated, recipients)
	if err != nil {
		return fmt.Errorf("re-encrypt: %w", err)
	}

	if err := os.WriteFile(encPath, newCiphertext, 0600); err != nil {
		return fmt.Errorf("write encrypted file: %w", err)
	}

	return nil
}

// EditOutputPath returns the default encrypted output path for a given .env file.
func EditOutputPath(envPath string) string {
	ext := filepath.Ext(envPath)
	base := strings.TrimSuffix(envPath, ext)
	return base + ".enc"
}

func openEditor(path string) error {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	cmd := exec.Command(editor, path)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
