package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLintLines_Clean(t *testing.T) {
	lines := []string{
		"# comment",
		"DATABASE_URL=postgres://localhost/db",
		"APP_PORT=8080",
		"",
		"SECRET_KEY=abc123",
	}
	issues := lintLines(lines)
	if len(issues) != 0 {
		t.Fatalf("expected no issues, got: %v", issues)
	}
}

func TestLintLines_LowercaseKey(t *testing.T) {
	lines := []string{"db_host=localhost"}
	issues := lintLines(lines)
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got %d: %v", len(issues), issues)
	}
}

func TestLintLines_DuplicateKey(t *testing.T) {
	lines := []string{
		"FOO=bar",
		"FOO=baz",
	}
	issues := lintLines(lines)
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue for duplicate, got %d: %v", len(issues), issues)
	}
}

func TestLintLines_UnquotedSpaces(t *testing.T) {
	lines := []string{"GREETING=hello world"}
	issues := lintLines(lines)
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue for unquoted spaces, got %d: %v", len(issues), issues)
	}
}

func TestLintLines_QuotedSpacesOK(t *testing.T) {
	lines := []string{`GREETING="hello world"`}
	issues := lintLines(lines)
	if len(issues) != 0 {
		t.Fatalf("expected no issues for quoted value, got: %v", issues)
	}
}

func TestLintLines_MissingSeparator(t *testing.T) {
	lines := []string{"BADLINE"}
	issues := lintLines(lines)
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue for missing '=', got %d", len(issues))
	}
}

func TestLintEnvFile(t *testing.T) {
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "key.txt")
	if err := GenerateIdentity(identityPath); err != nil {
		t.Fatal(err)
	}
	identity, err := LoadIdentity(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := IdentityToRecipient(identity)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("DB_HOST=localhost\nDB_PORT=5432\n")
	ciphertext, err := Encrypt(plaintext, []string{recipient.String()})
	if err != nil {
		t.Fatal(err)
	}

	encPath := filepath.Join(dir, "test.env.age")
	if err := os.WriteFile(encPath, ciphertext, 0600); err != nil {
		t.Fatal(err)
	}

	issues, err := LintEnvFile(encPath, identityPath)
	if err != nil {
		t.Fatalf("LintEnvFile error: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("expected no issues, got: %v", issues)
	}
}

func TestLintEnvFileMissingIdentity(t *testing.T) {
	dir := t.TempDir()
	_, err := LintEnvFile(filepath.Join(dir, "x.age"), filepath.Join(dir, "missing.txt"))
	if err == nil {
		t.Fatal("expected error for missing identity")
	}
}
