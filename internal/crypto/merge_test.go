package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func setupMergeIdentity(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "identity.txt")
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if err := SaveIdentity(id, idPath); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	return dir, idPath
}

func writeEncryptedEnvMerge(t *testing.T, dir, name, content, idPath string) string {
	t.Helper()
	id, err := LoadIdentity(idPath)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	enc, err := Encrypt([]byte(content), []string{IdentityToRecipient(id)})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, enc, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return p
}

func TestMergeEnvFiles(t *testing.T) {
	dir, idPath := setupMergeIdentity(t)
	basePath := writeEncryptedEnvMerge(t, dir, "base.env.age", "FOO=1\nBAR=2\n", idPath)
	srcPath := writeEncryptedEnvMerge(t, dir, "src.env.age", "BAR=99\nBAZ=3\n", idPath)
	outPath := filepath.Join(dir, "out.env.age")

	result, err := MergeEnvFiles(basePath, srcPath, idPath, outPath, false)
	if err != nil {
		t.Fatalf("MergeEnvFiles: %v", err)
	}

	if len(result.Added) != 1 || result.Added[0] != "BAZ" {
		t.Errorf("expected Added=[BAZ], got %v", result.Added)
	}
	if len(result.Skipped) != 1 || result.Skipped[0] != "BAR" {
		t.Errorf("expected Skipped=[BAR], got %v", result.Skipped)
	}
	if len(result.Overridden) != 0 {
		t.Errorf("expected no overrides, got %v", result.Overridden)
	}

	if _, err := os.Stat(outPath); err != nil {
		t.Errorf("output file not created: %v", err)
	}
}

func TestMergeEnvFilesOverwrite(t *testing.T) {
	dir, idPath := setupMergeIdentity(t)
	basePath := writeEncryptedEnvMerge(t, dir, "base.env.age", "FOO=1\nBAR=2\n", idPath)
	srcPath := writeEncryptedEnvMerge(t, dir, "src.env.age", "BAR=99\nBAZ=3\n", idPath)
	outPath := filepath.Join(dir, "out.env.age")

	result, err := MergeEnvFiles(basePath, srcPath, idPath, outPath, true)
	if err != nil {
		t.Fatalf("MergeEnvFiles overwrite: %v", err)
	}

	if len(result.Overridden) != 1 || result.Overridden[0] != "BAR" {
		t.Errorf("expected Overridden=[BAR], got %v", result.Overridden)
	}
	if len(result.Skipped) != 0 {
		t.Errorf("expected no skipped, got %v", result.Skipped)
	}
}

func TestMergeEnvFilesMissingBase(t *testing.T) {
	_, idPath := setupMergeIdentity(t)
	_, err := MergeEnvFiles("/no/such/base.age", "/no/such/src.age", idPath, "/tmp/out.age", false)
	if err == nil {
		t.Error("expected error for missing base file")
	}
}

func TestMergeOutputPath(t *testing.T) {
	got := MergeOutputPath("/some/dir/prod.env.age")
	want := "/some/dir/prod.env.merged.age"
	if got != want {
		t.Errorf("MergeOutputPath: got %q, want %q", got, want)
	}
}
