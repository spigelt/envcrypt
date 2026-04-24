package crypto

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
)

const RecipientsFile = ".env.recipients"

// LoadRecipients reads a recipients file and returns a slice of age recipients.
// Each line in the file should be a valid age public key (age1...).
func LoadRecipients(path string) ([]age.Recipient, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening recipients file: %w", err)
	}
	defer f.Close()

	var recipients []age.Recipient
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r, err := ParseRecipient(line)
		if err != nil {
			return nil, fmt.Errorf("parsing recipient %q: %w", line, err)
		}
		recipients = append(recipients, r)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading recipients file: %w", err)
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("no recipients found in %s", path)
	}
	return recipients, nil
}

// AddRecipient appends a public key to the recipients file, creating it if needed.
func AddRecipient(path, pubkey string) error {
	// Validate the key before writing
	if _, err := ParseRecipient(pubkey); err != nil {
		return fmt.Errorf("invalid recipient key: %w", err)
	}

	// Check for duplicates
	existing, err := readLines(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading existing recipients: %w", err)
	}
	for _, line := range existing {
		if strings.TrimSpace(line) == pubkey {
			return fmt.Errorf("recipient %s already exists in %s", pubkey, path)
		}
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("opening recipients file for writing: %w", err)
	}
	defer f.Close()

	_, err = fmt.Fprintln(f, pubkey)
	return err
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
