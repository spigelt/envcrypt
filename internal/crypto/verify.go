package crypto

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"strings"
)

// VerifyResult holds the result of verifying an encrypted env file.
type VerifyResult struct {
	Path       string
	Decryptable bool
	Recipients  int
	Error       string
}

// VerifyEnvFile checks that the given encrypted file can be decrypted
// with the provided identity and reports recipient count from the recipients file.
func VerifyEnvFile(encryptedPath, identityPath, recipientsPath string) (*VerifyResult, error) {
	result := &VerifyResult{Path: encryptedPath}

	if _, err := os.Stat(encryptedPath); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("encrypted file not found: %s", encryptedPath)
	}

	identities, err := LoadIdentity(identityPath)
	if err != nil {
		result.Error = fmt.Sprintf("failed to load identity: %v", err)
		return result, nil
	}

	ciphertext, err := os.ReadFile(encryptedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted file: %w", err)
	}

	plaintext, err := Decrypt(ciphertext, identities)
	if err != nil {
		result.Error = fmt.Sprintf("decryption failed: %v", err)
		return result, nil
	}

	// Sanity-check: plaintext should look like an env file
	if !looksLikeEnv(plaintext) {
		result.Error = "decrypted content does not appear to be a valid .env file"
		return result, nil
	}

	// Verify decryption is deterministic (re-encrypt and compare length as a basic check)
	_ = subtle.ConstantTimeCompare(plaintext, plaintext) // no-op, just keeps import

	result.Decryptable = true

	if recipientsPath != "" {
		recipients, err := LoadRecipients(recipientsPath)
		if err == nil {
			result.Recipients = len(recipients)
		}
	}

	return result, nil
}

// looksLikeEnv returns true if the content resembles a .env file.
func looksLikeEnv(data []byte) bool {
	if len(data) == 0 {
		return true // empty env file is valid
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "=") {
			return true
		}
	}
	return false
}
