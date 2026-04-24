package crypto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateIdentity(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if id == nil {
		t.Fatal("expected non-nil identity")
	}
	if !strings.HasPrefix(id.PublicKey(), "age1") {
		t.Errorf("public key should start with 'age1', got: %s", id.PublicKey())
	}
	if !strings.HasPrefix(id.String(), "AGE-SECRET-KEY-") {
		t.Errorf("private key should start with 'AGE-SECRET-KEY-', got: %s", id.String())
	}
}

func TestSaveAndLoadIdentity(t *testing.T) {
	tmpDir := t.TempDir()

	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("generating identity: %v", err)
	}

	keyPath, err := SaveIdentity(id, tmpDir)
	if err != nil {
		t.Fatalf("saving identity: %v", err)
	}

	if keyPath != filepath.Join(tmpDir, DefaultKeyFile) {
		t.Errorf("unexpected key path: %s", keyPath)
	}

	// Check file permissions
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected 0600 permissions, got %v", info.Mode().Perm())
	}

	// Load and verify round-trip
	loaded, err := LoadIdentity(keyPath)
	if err != nil {
		t.Fatalf("loading identity: %v", err)
	}
	if loaded.PublicKey() != id.PublicKey() {
		t.Errorf("public key mismatch: got %s, want %s", loaded.PublicKey(), id.PublicKey())
	}
}

func TestSaveIdentityAlreadyExists(t *testing.T) {
	tmpDir := t.TempDir()

	id, _ := GenerateIdentity()
	_, err := SaveIdentity(id, tmpDir)
	if err != nil {
		t.Fatalf("first save: %v", err)
	}

	_, err = SaveIdentity(id, tmpDir)
	if err == nil {
		t.Fatal("expected error on duplicate save, got nil")
	}
}

func TestParseRecipient(t *testing.T) {
	id, _ := GenerateIdentity()
	recipient, err := ParseRecipient(id.PublicKey())
	if err != nil {
		t.Fatalf("parsing recipient: %v", err)
	}
	if recipient == nil {
		t.Fatal("expected non-nil recipient")
	}
}
