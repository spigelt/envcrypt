package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DecryptEnvFile decrypts an encrypted .env file and returns the plaintext content.
func DecryptEnvFile(encryptedPath string, identityPaths []string) ([]byte, error) {
	if len(identityPaths) == 0 {
		return nil, fmt.Errorf("at least one identity file is required for decryption")
	}

	encryptedData, err := os.ReadFile(encryptedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted file %q: %w", encryptedPath, err)
	}

	identities := make([]string, 0, len(identityPaths))
	for _, p := range identityPaths {
		identity, err := LoadIdentity(p)
		if err != nil {
			return nil, fmt.Errorf("failed to load identity from %q: %w", p, err)
		}
		identities = append(identities, identity)
	}

	plaintext, err := Decrypt(encryptedData, identities)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// OutputPath derives the output path for a decrypted file.
// It strips the ".enc" suffix if present, otherwise appends ".dec".
func OutputPath(encryptedPath string) string {
	base := filepath.Base(encryptedPath)
	dir := filepath.Dir(encryptedPath)

	if strings.HasSuffix(base, ".enc") {
		base = strings.TrimSuffix(base, ".enc")
	} else {
		base = base + ".dec"
	}

	return filepath.Join(dir, base)
}
