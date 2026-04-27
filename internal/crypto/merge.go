package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// MergeResult holds the outcome of merging two env files.
type MergeResult struct {
	Added     []string
	Overridden []string
	Skipped   []string
}

// MergeEnvFiles decrypts two encrypted env files, merges their key-value pairs,
// and writes the result to outputPath encrypted for the given recipients.
// Keys in src take precedence over keys in base when overwrite is true;
// otherwise existing keys in base are preserved.
func MergeEnvFiles(basePath, srcPath, identityPath, outputPath string, overwrite bool) (*MergeResult, error) {
	identity, err := LoadIdentity(identityPath)
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}

	baseData, err := os.ReadFile(basePath)
	if err != nil {
		return nil, fmt.Errorf("read base file: %w", err)
	}

	srcData, err := os.ReadFile(srcPath)
	if err != nil {
		return nil, fmt.Errorf("read src file: %w", err)
	}

	basePlain, err := Decrypt(baseData, identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt base: %w", err)
	}

	srcPlain, err := Decrypt(srcData, identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt src: %w", err)
	}

	baseMap := parseEnvMap(string(basePlain))
	srcMap := parseEnvMap(string(srcPlain))

	result := &MergeResult{}
	merged := make(map[string]string)

	for k, v := range baseMap {
		merged[k] = v
	}

	for k, v := range srcMap {
		if _, exists := merged[k]; exists {
			if overwrite {
				merged[k] = v
				result.Overridden = append(result.Overridden, k)
			} else {
				result.Skipped = append(result.Skipped, k)
			}
		} else {
			merged[k] = v
			result.Added = append(result.Added, k)
		}
	}

	var sb strings.Builder
	for k, v := range merged {
		sb.WriteString(fmt.Sprintf("%s=%s\n", k, v))
	}

	recipientPath := filepath.Join(filepath.Dir(identityPath), "recipients.txt")
	recipients, err := LoadRecipients(recipientPath)
	if err != nil {
		recipients = nil
	}

	recipients = append(recipients, IdentityToRecipient(identity))

	encrypted, err := Encrypt([]byte(sb.String()), recipients)
	if err != nil {
		return nil, fmt.Errorf("encrypt merged: %w", err)
	}

	if err := os.WriteFile(outputPath, encrypted, 0600); err != nil {
		return nil, fmt.Errorf("write output: %w", err)
	}

	return result, nil
}

// MergeOutputPath returns the default output path for a merge operation.
func MergeOutputPath(basePath string) string {
	ext := filepath.Ext(basePath)
	base := strings.TrimSuffix(basePath, ext)
	return base + ".merged" + ext
}
