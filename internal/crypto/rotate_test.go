package crypto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotateKey(t *testing.T) {
	dir := t.TempDir()

	// Generate an identity
	identityPath := filepath.Join(dir, "identity.txt")
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if err := SaveIdentity(identity, identityPath); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	// Set up a recipients file with the identity's public key
	recipient := IdentityToRecipient(identity)
	refsPath := filepath.Join(dir, "recipients.txt")
	if err := os.WriteFile(refsPath, []byte(recipient.String()+"\n"), 0644); err != nil {
		t.Fatalf("write recipients: %v", err)
	}

	// Encrypt some plaintext
	plaintext := []byte("SECRET=hello\nOTHER=world\n")
	recipients, _ := LoadRecipients(refsPath)
	ciphertext, err := Encrypt(plaintext, recipients)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	encPath := filepath.Join(dir, ".env.age")
	if err := os.WriteFile(encPath, ciphertext, 0600); err != nil {
		t.Fatalf("write encrypted: %v", err)
	}

	// Rotate
	backupPath, err := RotateKey(encPath, identityPath, refsPath)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	// Backup file should exist
	if _, err := os.Stat(backupPath); err != nil {
		t.Errorf("backup file not found: %v", err)
	}

	// Rotated file should be decryptable with the same identity
	decrypted, err := DecryptEnvFile(encPath, identityPath)
	if err != nil {
		t.Fatalf("DecryptEnvFile after rotate: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted mismatch: got %q want %q", decrypted, plaintext)
	}
}

func TestRotateKeyMissingIdentity(t *testing.T) {
	dir := t.TempDir()
	_, err := RotateKey(
		filepath.Join(dir, ".env.age"),
		filepath.Join(dir, "missing.txt"),
		filepath.Join(dir, "recipients.txt"),
	)
	if err == nil {
		t.Fatal("expected error for missing identity")
	}
}

func TestRotateBackupPath(t *testing.T) {
	path := "/project/.env.age"
	backup := RotateBackupPath(path)
	if !strings.HasPrefix(backup, "/project/.env.") {
		t.Errorf("unexpected backup prefix: %s", backup)
	}
	if !strings.HasSuffix(backup, ".bak") {
		t.Errorf("backup should end with .bak, got: %s", backup)
	}
}
