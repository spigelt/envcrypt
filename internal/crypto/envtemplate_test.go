package crypto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupTemplateIdentity(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "key.txt")
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if err := SaveIdentity(identity, identityPath); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	return dir, identityPath
}

func writeEncryptedEnvTemplate(t *testing.T, dir, identityPath, content string) string {
	t.Helper()
	identity, err := LoadIdentity(identityPath)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	recipient := IdentityToRecipient(identity)
	ciphertext, err := Encrypt([]byte(content), []interface{ String() string }{recipient})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	encPath := filepath.Join(dir, ".env.age")
	if err := os.WriteFile(encPath, ciphertext, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return encPath
}

func TestTemplateOutputPath(t *testing.T) {
	cases := []struct {
		input, want string
	}{
		{".env.age", ".env.template"},
		{".env.enc", ".env.template"},
		{".env", ".env.template"},
	}
	for _, c := range cases {
		got := TemplateOutputPath(c.input)
		if got != c.want {
			t.Errorf("TemplateOutputPath(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestGenerateTemplate(t *testing.T) {
	dir, identityPath := setupTemplateIdentity(t)
	envContent := "# comment\nDB_HOST=localhost\nDB_PORT=5432\nSECRET_KEY=supersecret\n"
	encPath := writeEncryptedEnvTemplate(t, dir, identityPath, envContent)
	outPath := filepath.Join(dir, ".env.template")

	if err := GenerateTemplate(encPath, identityPath, outPath); err != nil {
		t.Fatalf("GenerateTemplate: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, "# comment") {
		t.Error("expected comment to be preserved")
	}
	if strings.Contains(got, "localhost") || strings.Contains(got, "supersecret") {
		t.Error("expected values to be stripped")
	}
	for _, key := range []string{"DB_HOST=", "DB_PORT=", "SECRET_KEY="} {
		if !strings.Contains(got, key) {
			t.Errorf("expected key %q in template", key)
		}
	}
}

func TestGenerateTemplateMissingIdentity(t *testing.T) {
	dir := t.TempDir()
	err := GenerateTemplate(
		filepath.Join(dir, ".env.age"),
		filepath.Join(dir, "missing.txt"),
		filepath.Join(dir, ".env.template"),
	)
	if err == nil {
		t.Fatal("expected error for missing identity")
	}
}
