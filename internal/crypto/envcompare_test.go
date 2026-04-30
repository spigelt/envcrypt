package crypto

import (
	"path/filepath"
	"strings"
	"testing"
)

func setupCompareIdentity(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "key.txt")
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if err := SaveIdentity(idPath, id); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	return dir, idPath
}

func writeCompareEnv(t *testing.T, dir, name, content, idPath string) string {
	t.Helper()
	id, _ := LoadIdentity(idPath)
	rec := IdentityToRecipient(id)
	encPath := filepath.Join(dir, name)
	if err := Encrypt([]byte(content), encPath, []string{rec.String()}); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return encPath
}

func TestCompareOutputPath(t *testing.T) {
	out := CompareOutputPath("/some/dir/prod.env.age", "/some/dir/staging.env.age")
	if out != "/some/dir/prod.env.compare.txt" {
		t.Errorf("unexpected output path: %s", out)
	}
}

func TestCompareEnvFiles(t *testing.T) {
	dir, idPath := setupCompareIdentity(t)
	a := writeCompareEnv(t, dir, "a.env.age", "FOO=1\nBAR=2\nSHARED=same\n", idPath)
	b := writeCompareEnv(t, dir, "b.env.age", "BAR=99\nSHARED=same\nBAZ=3\n", idPath)

	res, err := CompareEnvFiles(a, b, idPath)
	if err != nil {
		t.Fatalf("CompareEnvFiles: %v", err)
	}
	if len(res.OnlyInA) != 1 || res.OnlyInA[0] != "FOO" {
		t.Errorf("OnlyInA: %v", res.OnlyInA)
	}
	if len(res.OnlyInB) != 1 || res.OnlyInB[0] != "BAZ" {
		t.Errorf("OnlyInB: %v", res.OnlyInB)
	}
	if len(res.Different) != 1 || res.Different[0] != "BAR" {
		t.Errorf("Different: %v", res.Different)
	}
	if len(res.Identical) != 1 || res.Identical[0] != "SHARED" {
		t.Errorf("Identical: %v", res.Identical)
	}
}

func TestCompareEnvFilesNoChanges(t *testing.T) {
	dir, idPath := setupCompareIdentity(t)
	a := writeCompareEnv(t, dir, "a.env.age", "FOO=1\nBAR=2\n", idPath)
	b := writeCompareEnv(t, dir, "b.env.age", "FOO=1\nBAR=2\n", idPath)

	res, err := CompareEnvFiles(a, b, idPath)
	if err != nil {
		t.Fatalf("CompareEnvFiles: %v", err)
	}
	if len(res.OnlyInA)+len(res.OnlyInB)+len(res.Different) != 0 {
		t.Errorf("expected no differences")
	}
	if len(res.Identical) != 2 {
		t.Errorf("expected 2 identical, got %d", len(res.Identical))
	}
}

func TestCompareEnvFilesMissingIdentity(t *testing.T) {
	dir, idPath := setupCompareIdentity(t)
	a := writeCompareEnv(t, dir, "a.env.age", "FOO=1\n", idPath)
	b := writeCompareEnv(t, dir, "b.env.age", "FOO=1\n", idPath)
	_, err := CompareEnvFiles(a, b, "/nonexistent/key.txt")
	if err == nil {
		t.Error("expected error for missing identity")
	}
}

func TestFormatCompareResult(t *testing.T) {
	r := &CompareResult{
		OnlyInA:   []string{"FOO"},
		OnlyInB:   []string{"BAZ"},
		Different: []string{"BAR"},
		Identical: []string{"SHARED"},
	}
	out := FormatCompareResult("a.env.age", "b.env.age", r)
	for _, want := range []string{"FOO", "BAZ", "BAR", "SHARED", "a.env.age", "b.env.age"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}
