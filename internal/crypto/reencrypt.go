package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	age "filippo.io/age"
)

// ReencryptEnvFile decrypts an encrypted .env file using the provided identity
// and re-encrypts it for all current recipients in the recipients file.
func ReencryptEnvFile(encryptedPath, identityPath, recipientsPath string) error {
	identity, err := LoadIdentity(identityPath)
	if err != nil {
		return fmt.Errorf("loading identity: %w", err)
	}

	recipientLines, err := LoadRecipients(recipientsPath)
	if err != nil {
		return fmt.Errorf("loading recipients: %w", err)
	}

	if len(recipientLines) == 0 {
		return fmt.Errorf("no recipients found in %s", recipientsPath)
	}

	recipients := make([]age.Recipient, 0, len(recipientLines))
	for _, line := range recipientLines {
		r, err := ParseRecipient(line)
		if err != nil {
			return fmt.Errorf("parsing recipient %q: %w", line, err)
		}
		recipients = append(recipients, r)
	}

	ciphertext, err := os.ReadFile(encryptedPath)
	if err != nil {
		return fmt.Errorf("reading encrypted file: %w", err)
	}

	plaintext, err := Decrypt(ciphertext, identity)
	if err != nil {
		return fmt.Errorf("decrypting file: %w", err)
	}

	newCiphertext, err := Encrypt(plaintext, recipients)
	if err != nil {
		return fmt.Errorf("re-encrypting file: %w", err)
	}

	outPath := ReencryptOutputPath(encryptedPath)
	if err := os.WriteFile(outPath, newCiphertext, 0600); err != nil {
		return fmt.Errorf("writing re-encrypted file: %w", err)
	}

	return nil
}

// ReencryptOutputPath returns the output path for a re-encrypted file.
// It replaces .env.age with .env.age (same name) but writes to a temp name first.
func ReencryptOutputPath(encryptedPath string) string {
	dir := filepath.Dir(encryptedPath)
	base := filepath.Base(encryptedPath)
	if strings.HasSuffix(base, ".age") {
		return filepath.Join(dir, base)
	}
	return filepath.Join(dir, base+".age")
}
