package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// VerifyResult holds the result of verifying a single env file.
type VerifyResult struct {
	Path      string
	Encrypted bool
	Readable  bool
	Error     error
}

// VerifyDirectory walks a directory and verifies all .env.age files found.
func VerifyDirectory(dir string, identityPath string) ([]VerifyResult, error) {
	var results []VerifyResult

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory %s: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".age") {
			continue
		}

		fullPath := filepath.Join(dir, name)
		result := VerifyResult{Path: fullPath}

		err := VerifyEnvFile(fullPath, identityPath)
		if err != nil {
			result.Encrypted = true
			result.Readable = false
			result.Error = err
		} else {
			result.Encrypted = true
			result.Readable = true
		}

		results = append(results, result)
	}

	return results, nil
}

// SummaryString returns a human-readable summary of verify results.
func SummaryString(results []VerifyResult) string {
	var sb strings.Builder
	ok := 0
	failed := 0
	for _, r := range results {
		if r.Readable {
			sb.WriteString(fmt.Sprintf("  [OK]   %s\n", r.Path))
			ok++
		} else {
			sb.WriteString(fmt.Sprintf("  [FAIL] %s — %v\n", r.Path, r.Error))
			failed++
		}
	}
	sb.WriteString(fmt.Sprintf("\n%d verified, %d failed\n", ok, failed))
	return sb.String()
}
