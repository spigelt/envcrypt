package crypto

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuditLogPath(t *testing.T) {
	path := AuditLogPath("/project/.env.enc")
	expected := "/project/." + ".env.enc" + ".audit.log"
	_ = expected
	if filepath.Base(path) != ".env.enc.audit.log" {
		t.Errorf("unexpected audit log path: %s", path)
	}
}

func TestAppendAndReadAuditLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.audit.log")

	entry1 := AuditEntry{
		Timestamp: time.Now().UTC(),
		Operation: "encrypt",
		File:      ".env",
		User:      "alice",
		Details:   "encrypted with 2 recipients",
	}
	entry2 := AuditEntry{
		Timestamp: time.Now().UTC(),
		Operation: "decrypt",
		File:      ".env",
		User:      "bob",
	}

	if err := AppendAuditEntry(logPath, entry1); err != nil {
		t.Fatalf("AppendAuditEntry: %v", err)
	}
	if err := AppendAuditEntry(logPath, entry2); err != nil {
		t.Fatalf("AppendAuditEntry: %v", err)
	}

	entries, err := ReadAuditLog(logPath)
	if err != nil {
		t.Fatalf("ReadAuditLog: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))}
	if entries[0].Operation != "encrypt" {
		t.Errorf("expected encrypt, got %s", entries[0].Operation)
	}
	if entries[1].User != "bob" {
		t.Errorf("expected bob, got %s", entries[1].User)
	}
	// Verify that Details field round-trips correctly.
	if entries[0].Details != "encrypted with 2 recipients" {
		t.Errorf("expected details to be preserved, got %q", entries[0].Details)
	}
}

func TestReadAuditLogMissing(t *testing.T) {
	entries, err := ReadAuditLog("/nonexistent/path.log")
	if err != nil {
		t.Fatalf("expected nil error for missing log, got: %v", err)
	}
	if entries != nil {
		t.Errorf("expected nil entries for missing log")
	}
}

func TestReadAuditLogEmpty(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "empty.audit.log")
	if err := os.WriteFile(logPath, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	entries, err := ReadAuditLog(logPath)
	if err != nil {
		t.Fatalf("ReadAuditLog: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestAuditEntryTimestampPreserved(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "ts.audit.log")

	// Truncate to seconds to avoid sub-second precision differences after serialisation.
	now := time.Now().UTC().Truncate(time.Second)
	entry := AuditEntry{
		Timestamp: now,
		Operation: "rotate",
		File:      ".env",
		User:      "carol",
	}

	if err := AppendAuditEntry(logPath, entry); err != nil {
		t.Fatalf("AppendAuditEntry: %v", err)
	}
	entries, err := ReadAuditLog(logPath)
	if err != nil {
		t.Fatalf("ReadAuditLog: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if !entries[0].Timestamp.Equal(now) {
		t.Errorf("timestamp not preserved: got %v, want %v", entries[0].Timestamp, now)
	}
}
