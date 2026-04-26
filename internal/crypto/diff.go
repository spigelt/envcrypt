package crypto

import (
	"fmt"
	"sort"
	"strings"
)

// DiffResult holds the comparison between two decrypted env files.
type DiffResult struct {
	Added    []string
	Removed  []string
	Changed  []string
	Unchanged []string
}

// HasChanges returns true if there are any differences.
func (d *DiffResult) HasChanges() bool {
	return len(d.Added) > 0 || len(d.Removed) > 0 || len(d.Changed) > 0
}

// Summary returns a human-readable summary of the diff.
func (d *DiffResult) Summary() string {
	var sb strings.Builder
	for _, k := range d.Added {
		sb.WriteString(fmt.Sprintf("+ %s\n", k))
	}
	for _, k := range d.Removed {
		sb.WriteString(fmt.Sprintf("- %s\n", k))
	}
	for _, k := range d.Changed {
		sb.WriteString(fmt.Sprintf("~ %s\n", k))
	}
	if !d.HasChanges() {
		sb.WriteString("No differences found.\n")
	}
	return sb.String()
}

// parseEnvMap parses decrypted env content into a key→value map.
// Lines starting with '#' or empty lines are ignored.
func parseEnvMap(content string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		m[key] = val
	}
	return m
}

// DiffEnvFiles decrypts two encrypted env files and returns a DiffResult.
// identityPath is used to decrypt both files.
func DiffEnvFiles(fileA, fileB, identityPath string) (*DiffResult, error) {
	identity, err := LoadIdentity(identityPath)
	if err != nil {
		return nil, fmt.Errorf("loading identity: %w", err)
	}

	decA, err := Decrypt(fileA, identity)
	if err != nil {
		return nil, fmt.Errorf("decrypting %s: %w", fileA, err)
	}

	decB, err := Decrypt(fileB, identity)
	if err != nil {
		return nil, fmt.Errorf("decrypting %s: %w", fileB, err)
	}

	mapA := parseEnvMap(string(decA))
	mapB := parseEnvMap(string(decB))

	result := &DiffResult{}

	allKeys := make(map[string]struct{})
	for k := range mapA {
		allKeys[k] = struct{}{}
	}
	for k := range mapB {
		allKeys[k] = struct{}{}
	}

	keys := make([]string, 0, len(allKeys))
	for k := range allKeys {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		valA, inA := mapA[k]
		valB, inB := mapB[k]
		switch {
		case inA && !inB:
			result.Removed = append(result.Removed, k)
		case !inA && inB:
			result.Added = append(result.Added, k)
		case valA != valB:
			result.Changed = append(result.Changed, k)
		default:
			result.Unchanged = append(result.Unchanged, k)
		}
	}

	return result, nil
}
