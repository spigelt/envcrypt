package crypto

import (
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
)

const (
	DefaultKeyDir  = ".envcrypt"
	DefaultKeyFile = "identity.age"
)

// Identity wraps an age X25519 identity (private key).
type Identity struct {
	inner *age.X25519Identity
}

// GenerateIdentity creates a new age X25519 key pair.
func GenerateIdentity() (*Identity, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generating identity: %w", err)
	}
	return &Identity{inner: id}, nil
}

// PublicKey returns the recipient string (public key).
func (i *Identity) PublicKey() string {
	return i.inner.Recipient().String()
}

// String returns the private key string.
func (i *Identity) String() string {
	return i.inner.String()
}

// SaveIdentity writes the private key to disk under keyDir.
func SaveIdentity(id *Identity, keyDir string) (string, error) {
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return "", fmt.Errorf("creating key directory: %w", err)
	}

	keyPath := filepath.Join(keyDir, DefaultKeyFile)
	if _, err := os.Stat(keyPath); err == nil {
		return "", fmt.Errorf("identity file already exists at %s", keyPath)
	}

	content := fmt.Sprintf("# age identity file\n# public key: %s\n%s\n",
		id.PublicKey(), id.String())

	if err := os.WriteFile(keyPath, []byte(content), 0600); err != nil {
		return "", fmt.Errorf("writing identity file: %w", err)
	}

	return keyPath, nil
}

// LoadIdentity reads an age private key from the given file path.
func LoadIdentity(keyPath string) (*Identity, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading identity file: %w", err)
	}

	ids, err := age.ParseIdentities(bytesReader(data))
	if err != nil {
		return nil, fmt.Errorf("parsing identity: %w", err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no identities found in %s", keyPath)
	}

	x25519, ok := ids[0].(*age.X25519Identity)
	if !ok {
		return nil, fmt.Errorf("unsupported identity type")
	}
	return &Identity{inner: x25519}, nil
}
