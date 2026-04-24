package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDecryptEnvFile(t *testing.T) {
	dir := t.TempDir()

	identityPath := filepath.Join(dir, "identity.txt")
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if err := SaveIdentity(identity, identityPath); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	recipient, err := IdentityToRecipient(identity)
	if err != nil {
		t.Fatalf("IdentityToRecipient: %v", err)
	}

	plaintext := []byte("SECRET=hello\nDB_PASS=world\n")
	encrypted, err := Encrypt(plaintext, []string{recipient})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	encPath := filepath.Join(dir, ".env.enc")
	if err := os.WriteFile(encPath, encrypted, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := DecryptEnvFile(encPath, []string{identityPath})
	if err != nil {
		t.Fatalf("DecryptEnvFile: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("expected %q, got %q", plaintext, got)
	}
}

func TestDecryptEnvFileMissingIdentity(t *testing.T) {
	_, err := DecryptEnvFile("nonexistent.enc", []string{})
	if err == nil {
		t.Fatal("expected error for empty identity list")
	}
}

func TestDecryptEnvFileBadPath(t *testing.T) {
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "identity.txt")
	identity, _ := GenerateIdentity()
	_ = SaveIdentity(identity, identityPath)

	_, err := DecryptEnvFile("/nonexistent/path/.env.enc", []string{identityPath})
	if err == nil {
		t.Fatal("expected error for missing encrypted file")
	}
}

func TestOutputPath(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{".env.enc", ".env"},
		{"secrets.enc", "secrets"},
		{"/path/to/.env.enc", "/path/to/.env"},
		{".env", ".env.dec"},
		{"config.yaml", "config.yaml.dec"},
	}
	for _, tc := range cases {
		got := OutputPath(tc.input)
		if got != tc.expected {
			t.Errorf("OutputPath(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}
