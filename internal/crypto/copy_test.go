package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopyOutputPath(t *testing.T) {
	cases := []struct {
		src     string
		destEnv string
		want    string
	}{
		{"/project/.env.production.age", "staging", "/project/.env.staging.age"},
		{"/project/.env.staging.age", "development", "/project/.env.development.age"},
		{"/a/b/.env.age", "prod", "/a/b/.env.prod.age"},
	}
	for _, c := range cases {
		got := CopyOutputPath(c.src, c.destEnv)
		if got != c.want {
			t.Errorf("CopyOutputPath(%q, %q) = %q; want %q", c.src, c.destEnv, got, c.want)
		}
	}
}

func setupCopyIdentity(t *testing.T) (identityPath, recsPath, dir string) {
	t.Helper()
	dir = t.TempDir()

	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	identityPath = filepath.Join(dir, "key.txt")
	if err := SaveIdentity(id, identityPath); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	rec := IdentityToRecipient(id)
	recsPath = filepath.Join(dir, ".recipients")
	if err := os.WriteFile(recsPath, []byte(rec.String()+"\n"), 0600); err != nil {
		t.Fatalf("write recipients: %v", err)
	}
	return identityPath, recsPath, dir
}

func TestCopyEnvFile(t *testing.T) {
	identityPath, recsPath, dir := setupCopyIdentity(t)

	recipients, _ := LoadRecipients(recsPath)
	srcPath := filepath.Join(dir, ".env.production.age")
	plaintext := []byte("DB_HOST=localhost\nDB_PORT=5432\n")
	if err := Encrypt(srcPath, plaintext, recipients); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	destPath, err := CopyEnvFile(srcPath, "staging", identityPath)
	if err != nil {
		t.Fatalf("CopyEnvFile: %v", err)
	}

	expected := filepath.Join(dir, ".env.staging.age")
	if destPath != expected {
		t.Errorf("got dest %q; want %q", destPath, expected)
	}

	id, _ := LoadIdentity(identityPath)
	decrypted, err := Decrypt(destPath, id)
	if err != nil {
		t.Fatalf("Decrypt copied file: %v", err)
	}
	if decrypted != string(plaintext) {
		t.Errorf("decrypted content mismatch: got %q; want %q", decrypted, string(plaintext))
	}
}

func TestCopyEnvFileDestinationExists(t *testing.T) {
	identityPath, recsPath, dir := setupCopyIdentity(t)

	recipients, _ := LoadRecipients(recsPath)
	srcPath := filepath.Join(dir, ".env.production.age")
	if err := Encrypt(srcPath, []byte("KEY=val\n"), recipients); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Pre-create destination
	destPath := filepath.Join(dir, ".env.staging.age")
	if err := os.WriteFile(destPath, []byte("exists"), 0600); err != nil {
		t.Fatalf("pre-create dest: %v", err)
	}

	_, err := CopyEnvFile(srcPath, "staging", identityPath)
	if err == nil {
		t.Error("expected error when destination exists, got nil")
	}
}

func TestCopyEnvFileMissingIdentity(t *testing.T) {
	dir := t.TempDir()
	_, err := CopyEnvFile(filepath.Join(dir, ".env.production.age"), "staging", filepath.Join(dir, "missing.txt"))
	if err == nil {
		t.Error("expected error for missing identity, got nil")
	}
}
