package crypto

import (
	"bytes"
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

// IdentityToRecipient converts an Identity to its age Recipient.
func IdentityToRecipient(id *Identity) age.Recipient {
	return id.inner.Recipient()
}

// InnerIdentity exposes the underlying age.Identity for encryption use.
func InnerIdentity(id *Identity) age.Identity {
	return id.inner
}
