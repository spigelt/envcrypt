package crypto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempEncryptedEnv(t *testing.T, dir, name, content string, recipientPath string) string {
	t.Helper()
	identity, err := LoadIdentity(recipientPath)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	recipient, err := IdentityToRecipient(identity)
	if err != nil {
		t.Fatalf("IdentityToRecipient: %v", err)
	}
	outPath := filepath.Join(dir, name)
	if err := Encrypt([]byte(content), []string{recipient.String()}, outPath); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return outPath
}

func setupDiffIdentity(t *testing.T, dir string) string {
	t.Helper()
	keyPath := filepath.Join(dir, "key.age")
	if err := GenerateIdentity(keyPath); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	return keyPath
}

func TestParseEnvMap(t *testing.T) {
	content := "# comment\nFOO=bar\nBAZ=qux\n\nEMPTY="
	m := parseEnvMap(content)
	if m["FOO"] != "bar" {
		t.Errorf("expected FOO=bar, got %q", m["FOO"])
	}
	if m["BAZ"] != "qux" {
		t.Errorf("expected BAZ=qux, got %q", m["BAZ"])
	}
	if _, ok := m["#"]; ok {
		t.Error("comment line should not be parsed as key")
	}
	if m["EMPTY"] != "" {
		t.Errorf("expected EMPTY='', got %q", m["EMPTY"])
	}
}

func TestDiffEnvFiles(t *testing.T) {
	dir := t.TempDir()
	keyPath := setupDiffIdentity(t, dir)

	contentA := "FOO=bar\nBAZ=old\nONLY_A=yes\n"
	contentB := "FOO=bar\nBAZ=new\nONLY_B=yes\n"

	fileA := writeTempEncryptedEnv(t, dir, "a.env.age", contentA, keyPath)
	fileB := writeTempEncryptedEnv(t, dir, "b.env.age", contentB, keyPath)

	result, err := DiffEnvFiles(fileA, fileB, keyPath)
	if err != nil {
		t.Fatalf("DiffEnvFiles: %v", err)
	}

	if len(result.Added) != 1 || result.Added[0] != "ONLY_B" {
		t.Errorf("expected Added=[ONLY_B], got %v", result.Added)
	}
	if len(result.Removed) != 1 || result.Removed[0] != "ONLY_A" {
		t.Errorf("expected Removed=[ONLY_A], got %v", result.Removed)
	}
	if len(result.Changed) != 1 || result.Changed[0] != "BAZ" {
		t.Errorf("expected Changed=[BAZ], got %v", result.Changed)
	}
	if len(result.Unchanged) != 1 || result.Unchanged[0] != "FOO" {
		t.Errorf("expected Unchanged=[FOO], got %v", result.Unchanged)
	}
	if !result.HasChanges() {
		t.Error("expected HasChanges() to be true")
	}
}

func TestDiffEnvFilesNoChanges(t *testing.T) {
	dir := t.TempDir()
	keyPath := setupDiffIdentity(t, dir)
	content := "FOO=bar\nBAZ=qux\n"

	fileA := writeTempEncryptedEnv(t, dir, "a.env.age", content, keyPath)
	fileB := writeTempEncryptedEnv(t, dir, "b.env.age", content, keyPath)

	result, err := DiffEnvFiles(fileA, fileB, keyPath)
	if err != nil {
		t.Fatalf("DiffEnvFiles: %v", err)
	}
	if result.HasChanges() {
		t.Error("expected no changes")
	}
	if !strings.Contains(result.Summary(), "No differences") {
		t.Errorf("expected 'No differences' in summary, got: %s", result.Summary())
	}
}

func TestDiffEnvFilesMissingIdentity(t *testing.T) {
	dir := t.TempDir()
	_, err := DiffEnvFiles(
		filepath.Join(dir, "a.env.age"),
		filepath.Join(dir, "b.env.age"),
		filepath.Join(dir, "missing.age"),
	)
	if err == nil {
		t.Error("expected error for missing identity")
	}
	_ = os.Remove(filepath.Join(dir, "a.env.age"))
}
