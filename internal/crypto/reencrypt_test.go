package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReencryptEnvFile(t *testing.T) {
	dir := t.TempDir()

	// Generate identity and recipient
	identityPath := filepath.Join(dir, "identity.txt")
	recipientPath := filepath.Join(dir, ".env.recipients")
	encryptedPath := filepath.Join(dir, ".env.age")

	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if err := SaveIdentity(identity, identityPath); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	recipient := IdentityToRecipient(identity)
	if err := os.WriteFile(recipientPath, []byte(recipient.String()+"\n"), 0644); err != nil {
		t.Fatalf("writing recipients: %v", err)
	}

	// Encrypt original content
	original := []byte("SECRET=hello\nOTHER=world\n")
	r, err := ParseRecipient(recipient.String())
	if err != nil {
		t.Fatalf("ParseRecipient: %v", err)
	}
	ciphertext, err := Encrypt(original, []interface{ String() string }{recipient})
	_ = ciphertext
	_ = r

	// Use Encrypt properly
	imported, err := Encrypt(original, []interface{ String() string }{recipient})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if err := os.WriteFile(encryptedPath, imported, 0600); err != nil {
		t.Fatalf("writing encrypted: %v", err)
	}

	// Re-encrypt
	if err := ReencryptEnvFile(encryptedPath, identityPath, recipientPath); err != nil {
		t.Fatalf("ReencryptEnvFile: %v", err)
	}

	// Verify output is readable
	outPath := ReencryptOutputPath(encryptedPath)
	newCipher, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}

	loaded, err := LoadIdentity(identityPath)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	plain, err := Decrypt(newCipher, loaded)
	if err != nil {
		t.Fatalf("Decrypt after reencrypt: %v", err)
	}
	if string(plain) != string(original) {
		t.Errorf("expected %q, got %q", original, plain)
	}
}

func TestReencryptEnvFileMissingIdentity(t *testing.T) {
	dir := t.TempDir()
	err := ReencryptEnvFile(
		filepath.Join(dir, ".env.age"),
		filepath.Join(dir, "missing.txt"),
		filepath.Join(dir, ".env.recipients"),
	)
	if err == nil {
		t.Error("expected error for missing identity")
	}
}

func TestReencryptOutputPath(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"/project/.env.age", "/project/.env.age"},
		{"/project/.env", "/project/.env.age"},
		{"relative/.env.age", "relative/.env.age"},
	}
	for _, c := range cases {
		got := ReencryptOutputPath(c.input)
		if got != c.expected {
			t.Errorf("ReencryptOutputPath(%q) = %q, want %q", c.input, got, c.expected)
		}
	}
}
