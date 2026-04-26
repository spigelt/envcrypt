package crypto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyDirectory(t *testing.T) {
	dir := t.TempDir()

	// Generate identity and recipient
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	identityPath := filepath.Join(dir, "identity.txt")
	if err := SaveIdentity(id, identityPath); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	recipient := IdentityToRecipient(id)

	// Write and encrypt an env file
	envContent := []byte("FOO=bar\nBAZ=qux\n")
	envPath := filepath.Join(dir, "test.env")
	if err := os.WriteFile(envPath, envContent, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	agePath := filepath.Join(dir, "test.env.age")
	if err := EncryptFile(envPath, agePath, []string{recipient.String()}); err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}

	// Verify directory
	results, err := VerifyDirectory(dir, identityPath)
	if err != nil {
		t.Fatalf("VerifyDirectory: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Readable {
		t.Errorf("expected file to be readable, got error: %v", results[0].Error)
	}
}

func TestVerifyDirectoryMissing(t *testing.T) {
	_, err := VerifyDirectory("/nonexistent/dir", "")
	if err == nil {
		t.Fatal("expected error for missing directory")
	}
}

func TestSummaryString(t *testing.T) {
	results := []VerifyResult{
		{Path: "a.env.age", Encrypted: true, Readable: true},
		{Path: "b.env.age", Encrypted: true, Readable: false, Error: fmt.Errorf("bad key")},
	}
	summary := SummaryString(results)
	if !strings.Contains(summary, "[OK]") {
		t.Error("expected [OK] in summary")
	}
	if !strings.Contains(summary, "[FAIL]") {
		t.Error("expected [FAIL] in summary")
	}
	if !strings.Contains(summary, "1 verified, 1 failed") {
		t.Errorf("unexpected summary counts: %s", summary)
	}
}
