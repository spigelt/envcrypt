package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

// ReencryptEnvFile decrypts an existing encrypted .env file and re-encrypts it
// for all recipients listed in the given recipients file.
func ReencryptEnvFile(encryptedPath, identityPath, recipientsPath string) error {
	identity, err := LoadIdentity(identityPath)
	if err != nil {
		return fmt.Errorf("loading identity: %w", err)
	}

	recipients, err := LoadRecipients(recipientsPath)
	if err != nil {
		return fmt.Errorf("loading recipients: %w", err)
	}

	if len(recipients) == 0 {
		return fmt.Errorf("no recipients found in %s", recipientsPath)
	}

	encryptedData, err := os.ReadFile(encryptedPath)
	if err != nil {
		return fmt.Errorf("reading encrypted file: %w", err)
	}

	plaintext, err := Decrypt(encryptedData, []age.Identity{identity})
	if err != nil {
		return fmt.Errorf("decrypting file: %w", err)
	}

	ageRecipients := make([]age.Recipient, 0, len(recipients))
	for _, r := range recipients {
		ageRecipients = append(ageRecipients, r)
	}

	reencrypted, err := Encrypt(plaintext, ageRecipients)
	if err != nil {
		return fmt.Errorf("re-encrypting file: %w", err)
	}

	if err := os.WriteFile(encryptedPath, reencrypted, 0600); err != nil {
		return fmt.Errorf("writing re-encrypted file: %w", err)
	}

	return nil
}

// ReencryptOutputPath returns the default output path for a re-encrypted file.
// It mirrors the convention used by OutputPath in decrypt.go.
func ReencryptOutputPath(inputPath string) string {
	base := filepath.Base(inputPath)
	dir := filepath.Dir(inputPath)
	if strings.HasSuffix(base, ".enc") {
		return filepath.Join(dir, strings.TrimSuffix(base, ".enc"))
	}
	return filepath.Join(dir, base+".enc")
}
