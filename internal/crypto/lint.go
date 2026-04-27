package crypto

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// LintIssue represents a single linting problem found in a .env file.
type LintIssue struct {
	Line    int
	Message string
}

func (l LintIssue) String() string {
	return fmt.Sprintf("line %d: %s", l.Line, l.Message)
}

var (
	validKeyRe    = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	commentRe     = regexp.MustCompile(`^\s*#`)
	blankRe       = regexp.MustCompile(`^\s*$`)
	quotedValueRe = regexp.MustCompile(`^".*"$|^'.*'$`)
)

// LintEnvFile decrypts the env file at encryptedPath using the identity at
// identityPath and checks the plaintext for common style issues.
func LintEnvFile(encryptedPath, identityPath string) ([]LintIssue, error) {
	identity, err := LoadIdentity(identityPath)
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}

	ciphertext, err := os.ReadFile(encryptedPath)
	if err != nil {
		return nil, fmt.Errorf("read encrypted file: %w", err)
	}

	plaintext, err := Decrypt(ciphertext, []string{identityPath}, identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return lintLines(strings.Split(strings.TrimRight(string(plaintext), "\n"), "\n")), nil
}

func lintLines(lines []string) []LintIssue {
	var issues []LintIssue
	seen := map[string]int{}

	for i, raw := range lines {
		lineNum := i + 1

		if blankRe.MatchString(raw) || commentRe.MatchString(raw) {
			continue
		}

		eqIdx := strings.Index(raw, "=")
		if eqIdx < 0 {
			issues = append(issues, LintIssue{lineNum, "missing '=' separator"})
			continue
		}

		key := strings.TrimSpace(raw[:eqIdx])
		value := raw[eqIdx+1:]

		if !validKeyRe.MatchString(key) {
			issues = append(issues, LintIssue{lineNum, fmt.Sprintf("key %q should be uppercase with underscores only", key)})
		}

		if prev, ok := seen[key]; ok {
			issues = append(issues, LintIssue{lineNum, fmt.Sprintf("duplicate key %q (first seen on line %d)", key, prev)})
		} else {
			seen[key] = lineNum
		}

		if strings.Contains(value, " ") && !quotedValueRe.MatchString(value) {
			issues = append(issues, LintIssue{lineNum, fmt.Sprintf("value for %q contains spaces but is not quoted", key)})
		}
	}

	return issues
}
