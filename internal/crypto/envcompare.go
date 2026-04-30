package crypto

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// CompareResult holds the result of comparing two env files.
type CompareResult struct {
	OnlyInA    []string
	OnlyInB    []string
	Different  []string
	Identical  []string
}

// CompareOutputPath returns the output path for a compare report.
func CompareOutputPath(a, b string) string {
	base := strings.TrimSuffix(filepath.Base(a), ".age")
	return filepath.Join(filepath.Dir(a), base+".compare.txt")
}

// CompareEnvFiles decrypts two encrypted env files and compares their keys and values.
func CompareEnvFiles(encryptedA, encryptedB, identityPath string) (*CompareResult, error) {
	idA, err := LoadIdentity(identityPath)
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}

	plainA, err := Decrypt(encryptedA, idA)
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: %w", encryptedA, err)
	}

	plainB, err := Decrypt(encryptedB, idA)
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: %w", encryptedB, err)
	}

	mapA := parseEnvMap(string(plainA))
	mapB := parseEnvMap(string(plainB))

	result := &CompareResult{}

	for k, vA := range mapA {
		vB, exists := mapB[k]
		if !exists {
			result.OnlyInA = append(result.OnlyInA, k)
		} else if vA != vB {
			result.Different = append(result.Different, k)
		} else {
			result.Identical = append(result.Identical, k)
		}
	}

	for k := range mapB {
		if _, exists := mapA[k]; !exists {
			result.OnlyInB = append(result.OnlyInB, k)
		}
	}

	sort.Strings(result.OnlyInA)
	sort.Strings(result.OnlyInB)
	sort.Strings(result.Different)
	sort.Strings(result.Identical)

	return result, nil
}

// FormatCompareResult returns a human-readable string of the compare result.
func FormatCompareResult(a, b string, r *CompareResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Comparing %s <-> %s\n", filepath.Base(a), filepath.Base(b)))
	sb.WriteString(fmt.Sprintf("  Only in A (%d): %s\n", len(r.OnlyInA), strings.Join(r.OnlyInA, ", ")))
	sb.WriteString(fmt.Sprintf("  Only in B (%d): %s\n", len(r.OnlyInB), strings.Join(r.OnlyInB, ", ")))
	sb.WriteString(fmt.Sprintf("  Different  (%d): %s\n", len(r.Different), strings.Join(r.Different, ", ")))
	sb.WriteString(fmt.Sprintf("  Identical  (%d): %s\n", len(r.Identical), strings.Join(r.Identical, ", ")))
	return sb.String()
}
