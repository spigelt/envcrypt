package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// EnvFileInfo holds metadata about a discovered encrypted env file.
type EnvFileInfo struct {
	Path       string
	Name       string
	Recipients int
}

// ListEnvFiles scans a directory for encrypted .env files (*.env.age)
// and returns metadata about each one found.
func ListEnvFiles(dir string) ([]EnvFileInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("directory not found: %s", dir)
		}
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var files []EnvFileInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".age") {
			continue
		}
		fullPath := filepath.Join(dir, name)
		recipientCount := countRecipients(dir, name)
		files = append(files, EnvFileInfo{
			Path:       fullPath,
			Name:       name,
			Recipients: recipientCount,
		})
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Name < files[j].Name
	})

	return files, nil
}

// countRecipients attempts to load the recipients file associated with
// the encrypted env file and returns the count, or -1 if unavailable.
func countRecipients(dir, encName string) int {
	base := strings.TrimSuffix(encName, ".age")
	recipientsPath := filepath.Join(dir, base+".recipients")
	lines, err := readLines(recipientsPath)
	if err != nil {
		return -1
	}
	count := 0
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			count++
		}
	}
	return count
}

// FormatEnvList returns a human-readable table string for a list of EnvFileInfo.
func FormatEnvList(files []EnvFileInfo) string {
	if len(files) == 0 {
		return "No encrypted env files found."
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-40s %s\n", "FILE", "RECIPIENTS"))
	sb.WriteString(strings.Repeat("-", 52) + "\n")
	for _, f := range files {
		recStr := fmt.Sprintf("%d", f.Recipients)
		if f.Recipients < 0 {
			recStr = "unknown"
		}
		sb.WriteString(fmt.Sprintf("%-40s %s\n", f.Name, recStr))
	}
	return sb.String()
}
