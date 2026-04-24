package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRecipients(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	recipient := IdentityToRecipient(id)
	pubkey := recipient.String()

	tmp := filepath.Join(t.TempDir(), ".env.recipients")
	if err := os.WriteFile(tmp, []byte("# comment\n"+pubkey+"\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	recipients, err := LoadRecipients(tmp)
	if err != nil {
		t.Fatalf("LoadRecipients: %v", err)
	}
	if len(recipients) != 1 {
		t.Errorf("expected 1 recipient, got %d", len(recipients))
	}
}

func TestLoadRecipientsMissing(t *testing.T) {
	_, err := LoadRecipients("/nonexistent/.env.recipients")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadRecipientsEmpty(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), ".env.recipients")
	if err := os.WriteFile(tmp, []byte("# only comments\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := LoadRecipients(tmp)
	if err == nil {
		t.Error("expected error for empty recipients")
	}
}

func TestAddRecipient(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	pubkey := IdentityToRecipient(id).String()
	tmp := filepath.Join(t.TempDir(), ".env.recipients")

	if err := AddRecipient(tmp, pubkey); err != nil {
		t.Fatalf("AddRecipient: %v", err)
	}

	recipients, err := LoadRecipients(tmp)
	if err != nil {
		t.Fatalf("LoadRecipients after add: %v", err)
	}
	if len(recipients) != 1 {
		t.Errorf("expected 1 recipient, got %d", len(recipients))
	}
}

func TestAddRecipientDuplicate(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	pubkey := IdentityToRecipient(id).String()
	tmp := filepath.Join(t.TempDir(), ".env.recipients")

	if err := AddRecipient(tmp, pubkey); err != nil {
		t.Fatalf("first AddRecipient: %v", err)
	}
	if err := AddRecipient(tmp, pubkey); err == nil {
		t.Error("expected error on duplicate recipient")
	}
}

func TestAddRecipientInvalidKey(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), ".env.recipients")
	if err := AddRecipient(tmp, "not-a-valid-key"); err == nil {
		t.Error("expected error for invalid key")
	}
}
