package crypto

import (
	"bytes"
	"fmt"
	"io"

	"filippo.io/age"
)

// bytesReader wraps a byte slice in an io.Reader.
func bytesReader(data []byte) io.Reader {
	return bytes.NewReader(data)
}

// ParseRecipient parses an age public key string into a Recipient.
func ParseRecipient(pubKey string) (age.Recipient, error) {
	return age.ParseX25519Recipient(pubKey)
}

// ParseRecipients parses multiple age public key strings into a slice of Recipients.
// It returns an error if any key fails to parse, including the index and key in the message.
func ParseRecipients(pubKeys []string) ([]age.Recipient, error) {
	recipients := make([]age.Recipient, 0, len(pubKeys))
	for i, key := range pubKeys {
		r, err := age.ParseX25519Recipient(key)
		if err != nil {
			return nil, fmt.Errorf("invalid recipient at index %d (%q): %w", i, key, err)
		}
		recipients = append(recipients, r)
	}
	return recipients, nil
}

// IdentityToRecipient converts an Identity to its age Recipient.
func IdentityToRecipient(id *Identity) age.Recipient {
	return id.inner.Recipient()
}

// InnerIdentity exposes the underlying age.Identity for encryption use.
func InnerIdentity(id *Identity) age.Identity {
	return id.inner
}
