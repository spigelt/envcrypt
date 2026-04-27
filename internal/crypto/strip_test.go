package crypto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStripOutputPath(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{".env.age", ".env.stripped.age"},
		{"prod.env.age", "prod.env.stripped.age"},
		{"/secrets/.env.age", "/secrets/.env.stripped.age"},
	}
	for _, tc := range cases {
		got := StripOutputPath(tc.input)
		if got != tc.want {
			t.Errorf("StripOutputPath(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestStripLines(t *testing.T) {
	input := "# comment\nKEY=value\n\n# another comment\nFOO=bar\n"
	got := stripLines(input)
	if strings.Contains(got, "#") {
		t.Error("expected comments to be removed")
	}
	if strings.Contains(got, "\n\n") {
		t.Error("expected blank lines to be removed")
	}
	if !strings.Contains(got, "KEY=value") {
		t.Error("expected KEY=value to be present")
	}
	if !strings.Contains(got, "FOO=bar") {
		t.Error("expected FOO=bar to be present")
	}
}

func TestStripEnvFile(t *testing.T) {
	dir := t.TempDir()

	// Generate identity
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(dir, "identity.txt")
	if err := SaveIdentity(id, identityPath); err != nil {
		t.Fatal(err)
	}

	// Write recipients file
	recipient := IdentityToRecipient(id)
	recipientsPath := filepath.Join(dir, "recipients.txt")
	if err := os.WriteFile(recipientsPath, []byte(recipient.String()+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create plaintext env content with comments and blanks
	plain := "# This is a comment\nKEY=value\n\n# Another comment\nFOO=bar\n"
	recipients, _ := LoadRecipients(recipientsPath)
	ciphertext, err := Encrypt([]byte(plain), recipients)
	if err != nil {
		t.Fatal(err)
	}
	encryptedPath := filepath.Join(dir, ".env.age")
	if err := os.WriteFile(encryptedPath, ciphertext, 0600); err != nil {
		t.Fatal(err)
	}

	outputPath := StripOutputPath(encryptedPath)
	if err := StripEnvFile(encryptedPath, identityPath, recipientsPath, outputPath); err != nil {
		t.Fatalf("StripEnvFile: %v", err)
	}

	// Decrypt and verify output
	resultCipher, _ := os.ReadFile(outputPath)
	resultPlain, err := Decrypt(resultCipher, id)
	if err != nil {
		t.Fatalf("decrypt stripped: %v", err)
	}
	result := string(resultPlain)
	if strings.Contains(result, "#") {
		t.Error("stripped output should not contain comments")
	}
	if !strings.Contains(result, "KEY=value") || !strings.Contains(result, "FOO=bar") {
		t.Error("stripped output missing expected keys")
	}
}

func TestStripEnvFileMissingIdentity(t *testing.T) {
	dir := t.TempDir()
	err := StripEnvFile("nofile.age", filepath.Join(dir, "missing.txt"), "rec.txt", "out.age")
	if err == nil {
		t.Error("expected error for missing identity")
	}
}
