package crypto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestListEnvFiles(t *testing.T) {
	dir := t.TempDir()

	// Create some encrypted env files
	for _, name := range []string{"prod.env.age", "staging.env.age", "dev.env.age"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("data"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Create a non-.age file that should be ignored
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignore me"), 0600); err != nil {
		t.Fatal(err)
	}

	files, err := ListEnvFiles(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("expected 3 files, got %d", len(files))
	}
	// Should be sorted alphabetically
	if files[0].Name != "dev.env.age" {
		t.Errorf("expected dev.env.age first, got %s", files[0].Name)
	}
}

func TestListEnvFilesWithRecipients(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "prod.env.age"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	recipientsContent := "age1abc\nage1def\n"
	if err := os.WriteFile(filepath.Join(dir, "prod.env.recipients"), []byte(recipientsContent), 0600); err != nil {
		t.Fatal(err)
	}

	files, err := ListEnvFiles(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if files[0].Recipients != 2 {
		t.Errorf("expected 2 recipients, got %d", files[0].Recipients)
	}
}

func TestListEnvFilesMissingDir(t *testing.T) {
	_, err := ListEnvFiles("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for missing directory")
	}
	if !strings.Contains(err.Error(), "directory not found") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestListEnvFilesEmpty(t *testing.T) {
	dir := t.TempDir()
	files, err := ListEnvFiles(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
}

func TestFormatEnvList(t *testing.T) {
	files := []EnvFileInfo{
		{Name: "prod.env.age", Recipients: 3},
		{Name: "dev.env.age", Recipients: -1},
	}
	out := FormatEnvList(files)
	if !strings.Contains(out, "prod.env.age") {
		t.Error("expected prod.env.age in output")
	}
	if !strings.Contains(out, "unknown") {
		t.Error("expected 'unknown' for missing recipients")
	}
}

func TestFormatEnvListEmpty(t *testing.T) {
	out := FormatEnvList([]EnvFileInfo{})
	if !strings.Contains(out, "No encrypted env files found") {
		t.Errorf("unexpected output: %s", out)
	}
}
