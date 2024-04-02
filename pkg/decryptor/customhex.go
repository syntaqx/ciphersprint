package decryptor

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

// CustomHexDecryptor decodes paths encoded with a custom hex character set.
type CustomHexDecryptor struct{}

func (d *CustomHexDecryptor) Match(challenge challenge.ChallengeResponse) bool {
	return strings.Contains(challenge.EncryptionMethod, "encoded it with custom hex character set")
}

func (d *CustomHexDecryptor) Decrypt(challenge challenge.ChallengeResponse) (string, error) {
	// Use regex to extract the custom hex character set from the EncryptionMethod field
	re := regexp.MustCompile(`set\s+([0-9a-fA-F]{16})`)
	matches := re.FindStringSubmatch(challenge.EncryptionMethod)
	if len(matches) < 2 {
		return "", fmt.Errorf("failed to extract custom hex set from encryption method: %s", challenge.EncryptionMethod)
	}
	customHex := matches[1] // The captured custom hex set

	standardHex := "0123456789abcdef" // The standard hexadecimal character set

	// Remove the TaskPrefix from the encrypted path
	trimmedPath := strings.TrimPrefix(challenge.EncryptedPath, TaskPrefix)
	var decryptedPath strings.Builder

	for _, char := range trimmedPath {
		index := strings.IndexRune(customHex, char)
		if index == -1 {
			return "", fmt.Errorf("character '%c' not found in custom hex set", char)
		}
		decryptedPath.WriteByte(standardHex[index])
	}

	// Here, decryptedPath.String() may still represent hex-encoded data.
	// Additional processing might be needed to convert it into its final form.
	return TaskPrefix + decryptedPath.String(), nil
}
