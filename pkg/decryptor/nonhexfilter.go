package decryptor

import (
	"regexp"
	"strings"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

// NonHexFilterDecryptor removes non-hex characters from the encrypted path.
type NonHexFilterDecryptor struct{}

func (d *NonHexFilterDecryptor) Match(challenge challenge.ChallengeResponse) bool {
	return strings.Contains(challenge.EncryptionMethod, "inserted some non-hex characters")
}

func (d *NonHexFilterDecryptor) Decrypt(challenge challenge.ChallengeResponse) (string, error) {
	// Define a regular expression to match non-hexadecimal characters
	re := regexp.MustCompile(`[^0-9a-fA-F]`)

	trimmedPath := strings.TrimPrefix(challenge.EncryptedPath, TaskPrefix)
	// Filter out non-hex characfters
	filteredPath := re.ReplaceAllString(trimmedPath, "")

	return TaskPrefix + filteredPath, nil
}
