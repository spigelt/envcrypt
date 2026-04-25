package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// RotateKey generates a new identity, re-encrypts the env file with the new
// key added as a recipient, backs up the old identity, and saves the new one.
func RotateKey(envFile, identityFile string) error {
	// Load existing identity
	oldIdentity, err := LoadIdentity(identityFile)
	if err != nil {
		return fmt.Errorf("loading identity: %w", err)
	}

	// Load existing recipients
	recipientsFile := envFile + ".recipients"
	recipients, err := LoadRecipients(recipientsFile)
	if err != nil {
		return fmt.Errorf("loading recipients: %w", err)
	}

	// Generate new identity
	newIdentity, err := GenerateIdentity()
	if err != nil {
		return fmt.Errorf("generating new identity: %w", err)
	}

	// Add new recipient to the list
	newRecipient := IdentityToRecipient(newIdentity)
	if err := AddRecipient(recipientsFile, newRecipient.String()); err != nil {
		return fmt.Errorf("adding new recipient: %w", err)
	}

	// Re-encrypt env file with updated recipients (including new key)
	allRecipients := append(recipients, newRecipient)
	plaintext, err := DecryptEnvFile(envFile, identityFile)
	if err != nil {
		return fmt.Errorf("decrypting env file: %w", err)
	}

	ciphertext, err := Encrypt(plaintext, allRecipients)
	if err != nil {
		return fmt.Errorf("re-encrypting env file: %w", err)
	}

	if err := os.WriteFile(envFile, ciphertext, 0644); err != nil {
		return fmt.Errorf("writing re-encrypted env file: %w", err)
	}

	// Backup old identity
	backupPath := RotateBackupPath(identityFile)
	oldData, err := os.ReadFile(identityFile)
	if err != nil {
		return fmt.Errorf("reading old identity: %w", err)
	}
	if err := os.WriteFile(backupPath, oldData, 0600); err != nil {
		return fmt.Errorf("writing identity backup: %w", err)
	}

	// Remove old identity's public key from recipients
	oldRecipient := IdentityToRecipient(oldIdentity)
	_ = oldRecipient // removal from recipients file is a manual/future step

	// Save new identity over old path
	if err := os.Remove(identityFile); err != nil {
		return fmt.Errorf("removing old identity file: %w", err)
	}
	if err := SaveIdentity(newIdentity, identityFile); err != nil {
		return fmt.Errorf("saving new identity: %w", err)
	}

	return nil
}

// RotateBackupPath returns the backup path for an identity file during rotation.
func RotateBackupPath(identityFile string) string {
	dir := filepath.Dir(identityFile)
	base := filepath.Base(identityFile)
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	return filepath.Join(dir, base+".backup."+timestamp)
}
