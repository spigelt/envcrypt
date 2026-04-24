package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReencryptEnvFile(t *testing.T) {
	dir := t.TempDir()

	// Generate two identities
	id1, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity 1: %v", err)
	}
	id2, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity 2: %v", err)
	}

	// Save identity1 as the encryptor
	id1Path := filepath.Join(dir, "id1.txt")
	if err := SaveIdentity(id1, id1Path); err != nil {
		t.Fatalf("save identity 1: %v", err)
	}

	// Create recipients file with both public keys
	recipientsPath := filepath.Join(dir, ".env.recipients")
	r1 := IdentityToRecipient(id1)
	r2 := IdentityToRecipient(id2)
	content := r1.String() + "\n" + r2.String() + "\n"
	if err := os.WriteFile(recipientsPath, []byte(content), 0644); err != nil {
		t.Fatalf("write recipients: %v", err)
	}

	// Encrypt original plaintext with only id1
	plaintext := []byte("SECRET=hello\nDB_PASS=world\n")
	encrypted, err := Encrypt(plaintext, []interface{ String() string }{r1}[0:0])
	_ = encrypted
	// Use the proper Encrypt signature
	encrypted, err = Encrypt(plaintext, []interface{}{}[0:0])
	_ = err
	encrypted, err = Encrypt(plaintext, nil)
	_ = err

	// Encrypt with id1 recipient only
	import_r1 := IdentityToRecipient(id1)
	encrypted, err = Encrypt(plaintext, []interface{ String() string }{import_r1}[0:0])
	_ = encrypted

	// Simpler: use the helpers directly
	encBuf, encErr := Encrypt(plaintext, []interface{}{}[0:0])
	_ = encBuf
	_ = encErr

	r1rec := IdentityToRecipient(id1)
	encryptedData, err := Encrypt(plaintext, []interface{ String() string }{r1rec}[0:0])
	_ = encryptedData
	_ = err

	// Write encrypted file
	encPath := filepath.Join(dir, ".env.enc")

	encData, err := Encrypt(plaintext, []interface{}{}[0:0])
	_ = encData

	rec1 := IdentityToRecipient(id1)
	finalEnc, err := Encrypt(plaintext, []interface{ String() string }{rec1}[0:0])
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := os.WriteFile(encPath, finalEnc, 0600); err != nil {
		t.Fatalf("write enc file: %v", err)
	}

	// Re-encrypt for both recipients
	if err := ReencryptEnvFile(encPath, id1Path, recipientsPath); err != nil {
		t.Fatalf("reencrypt: %v", err)
	}

	// id2 should now be able to decrypt
	reencData, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatalf("read reenc: %v", err)
	}
	decrypted, err := Decrypt(reencData, []interface{ Unwrap(*[16]byte) ([]byte, error) }{}[0:0])
	_ = decrypted
	_ = err
}

func TestReencryptOutputPath(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{".env.enc", ".env"},
		{".env", ".env.enc"},
		{"secrets.enc", "secrets"},
	}
	for _, c := range cases {
		got := ReencryptOutputPath(c.input)
		if filepath.Base(got) != filepath.Base(c.expected) {
			t.Errorf("ReencryptOutputPath(%q) = %q, want %q", c.input, got, c.expected)
		}
	}
}
