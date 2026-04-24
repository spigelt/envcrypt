package crypto

import (
	"testing"

	"filippo.io/age"
)

func TestEncryptDecrypt(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("failed to generate identity: %v", err)
	}

	recipient := IdentityToRecipient(identity)
	plaintext := []byte("SECRET=hello\nAPI_KEY=world\n")

	ciphertext, err := Encrypt(plaintext, []age.Recipient{recipient})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Fatal("expected non-empty ciphertext")
	}

	decrypted, err := Decrypt(ciphertext, []age.Identity{identity})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("expected %q, got %q", plaintext, decrypted)
	}
}

func TestEncryptNoRecipients(t *testing.T) {
	_, err := Encrypt([]byte("data"), nil)
	if err == nil {
		t.Fatal("expected error when no recipients provided")
	}
}

func TestDecryptNoIdentities(t *testing.T) {
	_, err := Decrypt([]byte("data"), nil)
	if err == nil {
		t.Fatal("expected error when no identities provided")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	encryptIdentity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("failed to generate encrypt identity: %v", err)
	}

	wrongIdentity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("failed to generate wrong identity: %v", err)
	}

	recipient := IdentityToRecipient(encryptIdentity)
	ciphertext, err := Encrypt([]byte("SECRET=value"), []age.Recipient{recipient})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = Decrypt(ciphertext, []age.Identity{wrongIdentity})
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}

func TestEncryptMultipleRecipients(t *testing.T) {
	id1, _ := GenerateIdentity()
	id2, _ := GenerateIdentity()

	recipients := []age.Recipient{IdentityToRecipient(id1), IdentityToRecipient(id2)}
	plaintext := []byte("SHARED=secret")

	ciphertext, err := Encrypt(plaintext, recipients)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	for i, id := range []age.Identity{id1, id2} {
		decrypted, err := Decrypt(ciphertext, []age.Identity{id})
		if err != nil {
			t.Fatalf("recipient %d failed to decrypt: %v", i+1, err)
		}
		if string(decrypted) != string(plaintext) {
			t.Errorf("recipient %d: expected %q, got %q", i+1, plaintext, decrypted)
		}
	}
}
