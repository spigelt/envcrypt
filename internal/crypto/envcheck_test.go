package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func setupCheckIdentity(t *testing.T) (string, string) {
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

func writeCheckEnv(t *testing.T, dir, name, content, identityPath string) string {
	t.Helper()
	identity, err := LoadIdentity(identityPath)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	recipient, err := IdentityToRecipient(identity)
	if err != nil {
		t.Fatalf("IdentityToRecipient: %v", err)
	}
	encrypted, err := Encrypt([]byte(content), []string{recipient.String()})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, encrypted, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestCheckEnvFiles(t *testing.T) {
	dir, identityPath := setupCheckIdentity(t)
	baseline := writeCheckEnv(t, dir, "baseline.env.age", "FOO=1\nBAR=2\nBAZ=3\n", identityPath)
	target := writeCheckEnv(t, dir, "target.env.age", "FOO=1\nBAR=2\nNEW=4\n", identityPath)

	result, err := CheckEnvFiles(baseline, target, identityPath)
	if err != nil {
		t.Fatalf("CheckEnvFiles: %v", err)
	}
	if len(result.Missing) != 1 || result.Missing[0] != "BAZ" {
		t.Errorf("expected missing [BAZ], got %v", result.Missing)
	}
	if len(result.Extra) != 1 || result.Extra[0] != "NEW" {
		t.Errorf("expected extra [NEW], got %v", result.Extra)
	}
}

func TestCheckEnvFilesNoChanges(t *testing.T) {
	dir, identityPath := setupCheckIdentity(t)
	content := "FOO=1\nBAR=2\n"
	baseline := writeCheckEnv(t, dir, "baseline.env.age", content, identityPath)
	target := writeCheckEnv(t, dir, "target.env.age", content, identityPath)

	result, err := CheckEnvFiles(baseline, target, identityPath)
	if err != nil {
		t.Fatalf("CheckEnvFiles: %v", err)
	}
	if len(result.Missing) != 0 || len(result.Extra) != 0 {
		t.Errorf("expected no diff, got missing=%v extra=%v", result.Missing, result.Extra)
	}
}

func TestCheckEnvFilesMissingIdentity(t *testing.T) {
	dir, identityPath := setupCheckIdentity(t)
	baseline := writeCheckEnv(t, dir, "baseline.env.age", "FOO=1\n", identityPath)
	target := writeCheckEnv(t, dir, "target.env.age", "FOO=1\n", identityPath)

	_, err := CheckEnvFiles(baseline, target, "/nonexistent/key.txt")
	if err == nil {
		t.Error("expected error for missing identity")
	}
}

func TestCheckOutputPath(t *testing.T) {
	got := CheckOutputPath("/project/.env.age")
	want := "/project/.env.check.txt"
	if got != want {
		t.Errorf("CheckOutputPath = %q, want %q", got, want)
	}
}

func TestExtractKeys(t *testing.T) {
	content := "# comment\nFOO=bar\nBAR=baz\n\nINVALID\n"
	keys := extractKeys(content)
	if !keys["FOO"] || !keys["BAR"] {
		t.Errorf("expected FOO and BAR in keys, got %v", keys)
	}
	if keys["INVALID"] {
		t.Errorf("INVALID should not be in keys")
	}
}
