package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRenameOutputPath(t *testing.T) {
	cases := []struct {
		oldPath  string
		newName  string
		expected string
	}{
		{"/tmp/project/.env.enc", "production", "/tmp/project/production.enc"},
		{"/tmp/project/.env.enc", "staging.enc", "/tmp/project/staging.enc"},
		{"/tmp/project/dev", "prod", "/tmp/project/prod"},
	}
	for _, tc := range cases {
		got := RenameOutputPath(tc.oldPath, tc.newName)
		if got != tc.expected {
			t.Errorf("RenameOutputPath(%q, %q) = %q; want %q", tc.oldPath, tc.newName, got, tc.expected)
		}
	}
}

func TestRenameEnvFile(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, ".env.enc")
	if err := os.WriteFile(oldPath, []byte("encrypted"), 0600); err != nil {
		t.Fatal(err)
	}

	newPath, err := RenameEnvFile(oldPath, "production", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := filepath.Join(dir, "production.enc")
	if newPath != expected {
		t.Errorf("got %q; want %q", newPath, expected)
	}
	if _, err := os.Stat(newPath); err != nil {
		t.Errorf("renamed file not found: %v", err)
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Errorf("old file should not exist after rename")
	}
}

func TestRenameEnvFileMissingSource(t *testing.T) {
	dir := t.TempDir()
	_, err := RenameEnvFile(filepath.Join(dir, "missing.enc"), "new", "")
	if err == nil {
		t.Error("expected error for missing source file")
	}
}

func TestRenameEnvFileSameName(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, ".env.enc")
	_ = os.WriteFile(oldPath, []byte("data"), 0600)
	_, err := RenameEnvFile(oldPath, ".env", "")
	if err == nil {
		t.Error("expected error when new name resolves to same path")
	}
}

func TestRenameEnvFileDestinationExists(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, ".env.enc")
	newPath := filepath.Join(dir, "staging.enc")
	_ = os.WriteFile(oldPath, []byte("data"), 0600)
	_ = os.WriteFile(newPath, []byte("existing"), 0600)

	_, err := RenameEnvFile(oldPath, "staging", "")
	if err == nil {
		t.Error("expected error when destination already exists")
	}
}
