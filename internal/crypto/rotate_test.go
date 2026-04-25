package crypto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotateKey(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate initial identity and save it
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	identityFile := filepath.Join(tmpDir, "identity.txt")
	if err := SaveIdentity(identity, identityFile); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	// Create recipients file with the initial recipient
	envFile := filepath.Join(tmpDir, "test.env.age")
	recipientsFile := envFile + ".recipients"
	recipient := IdentityToRecipient(identity)
	if err := os.WriteFile(recipientsFile, []byte(recipient.String()+"\n"), 0644); err != nil {
		t.Fatalf("writing recipients: %v", err)
	}

	// Encrypt a sample env file
	plaintext := []byte("SECRET=hello\nANOTHER=world\n")
	ciphertext, err := Encrypt(plaintext, []interface{ String() string }{recipient})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if err := os.WriteFile(envFile, ciphertext, 0644); err != nil {
		t.Fatalf("writing env file: %v", err)
	}

	// Rotate the key
	if err := RotateKey(envFile, identityFile); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	// New identity should decrypt the env file
	decrypted, err := DecryptEnvFile(envFile, identityFile)
	if err != nil {
		t.Fatalf("DecryptEnvFile after rotate: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted content mismatch: got %q want %q", decrypted, plaintext)
	}

	// A backup of the old identity should exist
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	backupFound := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "identity.txt.backup.") {
			backupFound = true
		}
	}
	if !backupFound {
		t.Error("expected backup identity file, none found")
	}
}

func TestRotateKeyMissingIdentity(t *testing.T) {
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, "test.env.age")
	identityFile := filepath.Join(tmpDir, "nonexistent.txt")

	err := RotateKey(envFile, identityFile)
	if err == nil {
		t.Fatal("expected error for missing identity, got nil")
	}
}

func TestRotateBackupPath(t *testing.T) {
	path := RotateBackupPath("/home/user/.envcrypt/identity.txt")
	if !strings.HasPrefix(path, "/home/user/.envcrypt/identity.txt.backup.") {
		t.Errorf("unexpected backup path: %s", path)
	}
	// Timestamp portion should be present
	parts := strings.Split(path, ".backup.")
	if len(parts) != 2 || len(parts[1]) == 0 {
		t.Errorf("backup path missing timestamp: %s", path)
	}
}
