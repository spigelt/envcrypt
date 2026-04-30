package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CheckResult holds the result of checking a single env file for missing keys.
type CheckResult struct {
	File    string
	Missing []string
	Extra   []string
}

// CheckEnvFiles compares two encrypted env files and reports keys present in
// baseline but missing in target, and keys in target not present in baseline.
func CheckEnvFiles(baselinePath, targetPath, identityPath string) (*CheckResult, error) {
	identity, err := LoadIdentity(identityPath)
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}

	baselineData, err := os.ReadFile(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}

	targetData, err := os.ReadFile(targetPath)
	if err != nil {
		return nil, fmt.Errorf("read target: %w", err)
	}

	baselinePlain, err := Decrypt(baselineData, identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt baseline: %w", err)
	}

	targetPlain, err := Decrypt(targetData, identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt target: %w", err)
	}

	baselineKeys := extractKeys(string(baselinePlain))
	targetKeys := extractKeys(string(targetPlain))

	result := &CheckResult{File: targetPath}

	for k := range baselineKeys {
		if !targetKeys[k] {
			result.Missing = append(result.Missing, k)
		}
	}

	for k := range targetKeys {
		if !baselineKeys[k] {
			result.Extra = append(result.Extra, k)
		}
	}

	return result, nil
}

// CheckOutputPath returns the default output path for check reports.
func CheckOutputPath(targetPath string) string {
	dir := filepath.Dir(targetPath)
	base := strings.TrimSuffix(filepath.Base(targetPath), filepath.Ext(targetPath))
	return filepath.Join(dir, base+".check.txt")
}

func extractKeys(content string) map[string]bool {
	keys := make(map[string]bool)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.IndexByte(line, '='); idx > 0 {
			keys[strings.TrimSpace(line[:idx])] = true
		}
	}
	return keys
}
