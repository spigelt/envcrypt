package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyEnvFile(t *testing.T) {
	dir := t.TempDir()

	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	identityPath := filepath.Join(dir, "identity.txt")
	if err := SaveIdentity(identity, identityPath); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	recipient := IdentityToRecipient(identity)
	plaintext := []byte("DB_HOST=localhost\nDB_PORT=5432\n")
	ciphertext, err := Encrypt(plaintext, []string{recipient.String()})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	encryptedPath := filepath.Join(dir, "test.env.age")
	if err := os.WriteFile(encryptedPath, ciphertext, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	recsPath := filepath.Join(dir, "recipients.txt")
	if err := os.WriteFile(recsPath, []byte(recipient.String()+"\n"), 0600); err != nil {
		t.Fatalf("WriteFile recipients: %v", err)
	}

	result, err := VerifyEnvFile(encryptedPath, identityPath, recsPath)
	if err != nil {
		t.Fatalf("VerifyEnvFile error: %v", err)
	}
	if !result.Decryptable {
		t.Errorf("expected Decryptable=true, got false; error: %s", result.Error)
	}
	if result.Recipients != 1 {
		t.Errorf("expected 1 recipient, got %d", result.Recipients)
	}
}

func TestVerifyEnvFileMissingFile(t *testing.T) {
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "identity.txt")
	_, err := VerifyEnvFile(filepath.Join(dir, "missing.env.age"), identityPath, "")
	if err == nil {
		t.Error("expected error for missing encrypted file")
	}
}

func TestVerifyEnvFileWrongKey(t *testing.T) {
	dir := t.TempDir()

	encryptor, _ := GenerateIdentity()
	wrongIdentity, _ := GenerateIdentity()

	wrongPath := filepath.Join(dir, "wrong.txt")
	if err := SaveIdentity(wrongIdentity, wrongPath); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	recipient := IdentityToRecipient(encryptor)
	plaintext := []byte("KEY=value\n")
	ciphertext, err := Encrypt(plaintext, []string{recipient.String()})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	encryptedPath := filepath.Join(dir, "test.env.age")
	if err := os.WriteFile(encryptedPath, ciphertext, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	result, err := VerifyEnvFile(encryptedPath, wrongPath, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decryptable {
		t.Error("expected Decryptable=false with wrong key")
	}
}

func TestLooksLikeEnv(t *testing.T) {
	if !looksLikeEnv([]byte("KEY=value\n")) {
		t.Error("expected valid env content to pass")
	}
	if !looksLikeEnv([]byte("# comment\nKEY=value")) {
		t.Error("expected commented env to pass")
	}
	if !looksLikeEnv([]byte{}) {
		t.Error("expected empty content to pass")
	}
}
