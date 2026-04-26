package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEditOutputPath(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{".env", ".enc"},
		{".env.enc", ".env.enc"},
		{"secrets.env", "secrets.enc"},
		{"path/to/.env", "path/to/.enc"},
	}
	for _, tc := range cases {
		got := EditOutputPath(tc.input)
		if got != tc.expected {
			t.Errorf("EditOutputPath(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestEditEnvFileMissingIdentity(t *testing.T) {
	dir := t.TempDir()
	encPath := filepath.Join(dir, "test.enc")
	_ = os.WriteFile(encPath, []byte("dummy"), 0600)

	err := EditEnvFile(encPath, filepath.Join(dir, "missing.txt"), filepath.Join(dir, "recipients.txt"))
	if err == nil {
		t.Fatal("expected error for missing identity")
	}
}

func TestEditEnvFileBadEncryptedFile(t *testing.T) {
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "key.txt")
	recipientsPath := filepath.Join(dir, "recipients.txt")

	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveIdentity(id, identityPath); err != nil {
		t.Fatal(err)
	}
	recipient := IdentityToRecipient(id).String()
	if err := os.WriteFile(recipientsPath, []byte(recipient+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	encPath := filepath.Join(dir, "test.enc")
	_ = os.WriteFile(encPath, []byte("not valid age ciphertext"), 0600)

	err = EditEnvFile(encPath, identityPath, recipientsPath)
	if err == nil {
		t.Fatal("expected error decrypting invalid ciphertext")
	}
}

func TestEditEnvFileMissingEncryptedFile(t *testing.T) {
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "key.txt")
	recipientsPath := filepath.Join(dir, "recipients.txt")

	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveIdentity(id, identityPath); err != nil {
		t.Fatal(err)
	}
	recipient := IdentityToRecipient(id).String()
	_ = os.WriteFile(recipientsPath, []byte(recipient+"\n"), 0600)

	err = EditEnvFile(filepath.Join(dir, "nonexistent.enc"), identityPath, recipientsPath)
	if err == nil {
		t.Fatal("expected error for missing encrypted file")
	}
}
