package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// RotateKey decrypts an env file with the old identity, then re-encrypts it
// with all current recipients plus an optional new recipient public key.
// The original encrypted file is backed up before rotation.
func RotateKey(encryptedPath, identityPath, recipientsPath string) (string, error) {
	// Load the identity used to decrypt
	identity, err := LoadIdentity(identityPath)
	if err != nil {
		return "", fmt.Errorf("rotate: load identity: %w", err)
	}

	// Decrypt the existing file to plaintext bytes
	plaintext, err := DecryptEnvFile(encryptedPath, identityPath)
	if err != nil {
		return "", fmt.Errorf("rotate: decrypt: %w", err)
	}

	// Load current recipients
	recipients, err := LoadRecipients(recipientsPath)
	if err != nil {
		return "", fmt.Errorf("rotate: load recipients: %w", err)
	}

	if len(recipients) == 0 {
		return "", fmt.Errorf("rotate: no recipients found in %s", recipientsPath)
	}

	// Include the caller's own public key as a recipient so they can decrypt
	ownRecipient := IdentityToRecipient(identity)
	recipients = append(recipients, ownRecipient)

	// Encrypt plaintext with all recipients
	ciphertext, err := Encrypt(plaintext, recipients)
	if err != nil {
		return "", fmt.Errorf("rotate: encrypt: %w", err)
	}

	// Back up the original file
	backupPath := RotateBackupPath(encryptedPath)
	original, err := os.ReadFile(encryptedPath)
	if err != nil {
		return "", fmt.Errorf("rotate: read original: %w", err)
	}
	if err := os.WriteFile(backupPath, original, 0600); err != nil {
		return "", fmt.Errorf("rotate: write backup: %w", err)
	}

	// Write the newly encrypted file
	if err := os.WriteFile(encryptedPath, ciphertext, 0600); err != nil {
		return "", fmt.Errorf("rotate: write rotated file: %w", err)
	}

	return backupPath, nil
}

// RotateBackupPath returns a timestamped backup path for the given file.
func RotateBackupPath(encryptedPath string) string {
	ext := filepath.Ext(encryptedPath)
	base := encryptedPath[:len(encryptedPath)-len(ext)]
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	return fmt.Sprintf("%s.%s.bak", base, timestamp)
}
