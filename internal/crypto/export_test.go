package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExportPlaintext(t *testing.T) {
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "key.txt")
	encryptedPath := filepath.Join(dir, "test.env.age")
	outputPath := filepath.Join(dir, "test.env")

	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if err := SaveIdentity(identity, identityPath); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	recipient := IdentityToRecipient(identity)
	plaintext := []byte("DB_HOST=localhost\nDB_PORT=5432\n")
	ciphertext, err := Encrypt(plaintext, []string{recipient.String()})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if err := os.WriteFile(encryptedPath, ciphertext, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := ExportPlaintext(encryptedPath, identityPath, outputPath); err != nil {
		t.Fatalf("ExportPlaintext: %v", err)
	}

	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("expected %q, got %q", plaintext, got)
	}
}

func TestExportPlaintextMissingIdentity(t *testing.T) {
	dir := t.TempDir()
	err := ExportPlaintext(filepath.Join(dir, "x.env.age"), filepath.Join(dir, "missing.txt"), filepath.Join(dir, "out"))
	if err == nil {
		t.Error("expected error for missing identity")
	}
}

func TestExportPlaintextBadPath(t *testing.T) {
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "key.txt")
	identity, _ := GenerateIdentity()
	_ = SaveIdentity(identity, identityPath)

	err := ExportPlaintext(filepath.Join(dir, "nonexistent.age"), identityPath, filepath.Join(dir, "out"))
	if err == nil {
		t.Error("expected error for missing encrypted file")
	}
}

func TestExportOutputPath(t *testing.T) {
	cases := []struct {
		input, expected string
	}{
		{".env.age", ".env"},
		{"secrets.env.age", "secrets.env"},
		{".env", ".env.plain"},
		{"file", "file.plain"},
	}
	for _, c := range cases {
		got := ExportOutputPath(c.input)
		if got != c.expected {
			t.Errorf("ExportOutputPath(%q) = %q, want %q", c.input, got, c.expected)
		}
	}
}
